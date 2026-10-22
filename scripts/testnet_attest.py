"""End-to-end proof run on the Stellar TESTNET (never mainnet, never real funds).

1. create or load 3 wallets (operator, agent_good = mcp__weather, agent_bad =
   mcp__calc), fund new ones with Friendbot;
2. run a ReputationAirlock over the demo requests until the poisoned calc
   server is blocked, while the honest weather server stays clean;
3. bind subjects to local agent ids, build attestation documents, publish
   their hashes on testnet and verify them from Horizon;
4. tamper check, then a FRESH Airlock inherits reputation from the ledger;
5. write docs/testnet/proofs.json and docs/TESTNET_PROOFS.md.

Secrets live only in /root/hack/airlock-testnet/keys.json (chmod 600) and are
never printed. Usage: python scripts/testnet_attest.py
"""

from __future__ import annotations

import copy
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from airlock.attest import (  # noqa: E402
    NETWORK,
    account_exists,
    attestation_document,
    data_key,
    doc_hash,
    explorer_account,
    explorer_tx,
    friendbot,
    publish,
    seed_from_chain,
    verify,
)
from airlock.policy import HARNESS_POLICY  # noqa: E402
from airlock.reputation import ReputationAirlock, ReputationBook  # noqa: E402

KEYS = Path(os.environ.get("AIRLOCK_TESTNET_KEYS", "/root/hack/airlock-testnet/keys.json"))
OUT = ROOT / "docs" / "testnet"
MD = ROOT / "docs" / "TESTNET_PROOFS.md"
ROLES = {
    "operator": "Airlock operator (signs attestations)",
    "agent_good": "honest MCP server mcp__weather",
    "agent_bad": "MCP server mcp__calc (ships the poisoned tool)",
}
POISONED = "mcp__calc__add_numbers"


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(rel: str) -> dict[str, Any]:
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_or_create_keys() -> dict[str, Any]:
    from stellar_sdk import Keypair

    KEYS.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(KEYS.parent, 0o700)
    data = json.loads(KEYS.read_text(encoding="utf-8")) if KEYS.exists() else {}
    changed = False
    for role in ROLES:
        if role not in data:
            kp = Keypair.random()
            data[role] = {"public": kp.public_key, "secret": kp.secret}
            changed = True
    if changed:
        fd = os.open(KEYS, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    os.chmod(KEYS, 0o600)
    return {role: Keypair.from_secret(data[role]["secret"]) for role in ROLES}


def summary(decision: Any) -> dict[str, Any]:
    rules = sorted({f.rule_id for f in decision.findings})
    return {
        "quarantined_tools": list(decision.quarantined_tools),
        "rules": rules,
        "reputation_flag": any(r.startswith("REP-") for r in rules),
        "forwarded_tools": [t.get("name") for t in (decision.body or {}).get("tools", [])],
    }


def main() -> int:
    started = now()
    print(f"[{started}] Airlock x Stellar TESTNET proof run ({NETWORK})")

    # a. wallets
    keys = load_or_create_keys()
    wallets: dict[str, Any] = {}
    for role, kp in keys.items():
        existed = account_exists(kp.public_key)
        if not existed:
            friendbot(kp.public_key)
        wallets[role] = {
            "public_key": kp.public_key,
            "role": ROLES[role],
            "funded_by_friendbot_this_run": not existed,
            "explorer": explorer_account(kp.public_key),
        }
        status = "(exists)" if existed else "(funded now)"
        print(f"  wallet {role:10s} {kp.public_key} {status}")

    # b. reputation from real traffic
    book = ReputationBook()
    firewall = ReputationAirlock(book, policy=HARNESS_POLICY)
    poison = load_json("demo/requests/02_mcp_poisoning.json")
    forecast = load_json("demo/rugpull_before.json")["tools"][0]
    clean = load_json("demo/rugpull_before.json")
    rounds: list[dict[str, Any]] = []
    order = [(0, 1, 2), (1, 0, 2), (2, 1, 0), (1, 2, 0), (0, 2, 1), (2, 0, 1)]
    for i in range(12):
        body = copy.deepcopy(poison)
        tools = [*body["tools"], copy.deepcopy(forecast)]
        body["tools"] = [tools[j] for j in order[i % len(order)]]
        decision = firewall.inspect(body, trace_id=f"poison-{i + 1}")
        rounds.append({"request": f"02_mcp_poisoning #{i + 1}", **summary(decision),
                       "calc_score": book.score("server:calc")})
        firewall.inspect(copy.deepcopy(clean), trace_id=f"clean-{i + 1}")
        if book.level("server:calc") == "blocked" and book.level(f"tool:{POISONED}") == "blocked":
            break
    # c. identities (on Stellar the agent identity is the wallet address)
    agents = {"server:calc": keys["agent_bad"].public_key,
              "server:weather": keys["agent_good"].public_key}
    book.bind("server:calc", 1, registry=f"{NETWORK}:{agents['server:calc']}")
    book.bind("server:weather", 2, registry=f"{NETWORK}:{agents['server:weather']}")
    snap = book.snapshot()
    print(f"  scores after {len(rounds)} poisoned + {len(rounds)} clean requests:")
    for subject, info in snap.items():
        print(f"    {subject:40s} {info['score']:3d} {info['level']}")

    # d. documents, publish, verify
    operator = keys["operator"]
    docs: dict[str, dict[str, Any]] = {}
    txs: dict[str, str] = {}
    checks: dict[str, Any] = {}
    for name, subject in (("calc", "server:calc"), ("weather", "server:weather")):
        doc = attestation_document(book, subject, operator.public_key, agents[subject])
        path = OUT / f"attestation-{name}.json"
        write_json(path, doc)
        doc = json.loads(path.read_text(encoding="utf-8"))  # publish exactly what is on disk
        docs[name] = doc
        txs[name] = publish(operator, agents[subject], doc)
        print(f"  published {subject} score {doc['score']} -> {explorer_tx(txs[name])}")
    for name in docs:
        checks[name] = verify(txs[name], docs[name])
        print(f"  verify {name}: ok={checks[name]['ok']} {checks[name]['checks']}")

    # e. tamper check (never published)
    tampered = copy.deepcopy(docs["calc"])
    tampered["score"] = 95
    tamper = verify(txs["calc"], tampered)
    print(f"  tampered calc doc (score 95) verify ok={tamper['ok']} "
          f"memo_is_doc_hash={tamper['checks']['memo_is_doc_hash']}")

    # f. reputation from the ledger in a fresh instance
    fresh_book = ReputationBook()
    fresh = ReputationAirlock(fresh_book, policy=HARNESS_POLICY)
    reports = seed_from_chain(fresh_book, [(tampered, txs["calc"]),
                                           (docs["calc"], txs["calc"]),
                                           (docs["weather"], txs["weather"])])
    labels = ["tampered copy (score 95)", "attestation-calc.json", "attestation-weather.json"]
    for report, label in zip(reports, labels, strict=True):
        report["document"] = label
    # a second seeded instance, so the clean-looking request is also its first request
    # (no tool fingerprint pinned by an earlier request, hence no rug-pull finding)
    fresh2_book = ReputationBook()
    seed_from_chain(fresh2_book, [(docs["calc"], txs["calc"]), (docs["weather"], txs["weather"])])
    fresh2 = ReputationAirlock(fresh2_book, policy=HARNESS_POLICY)
    baseline = ReputationAirlock(ReputationBook(), policy=HARNESS_POLICY)
    benign = copy.deepcopy(poison)
    benign["tools"][0] = {
        "name": POISONED,
        "description": "Adds two numbers and returns the sum.",
        "input_schema": {"type": "object",
                         "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
                         "required": ["a", "b"]},
    }
    ledger = {
        "seed_reports": [{k: r[k] for k in ("document", "subject", "tx_hash", "ok", "seeded")}
                         | {"failed_checks": [c for c, v in r["verify"]["checks"].items() if not v]}
                         for r in reports],
        "fresh_scores": {s: {"score": v["score"], "level": v["level"], "source": v["source"]}
                         for s, v in fresh_book.snapshot().items()},
        "poisoned_request": {
            "seeded_from_chain": summary(fresh.inspect(copy.deepcopy(poison), trace_id="ledger-1")),
            "fresh_without_seed": summary(baseline.inspect(copy.deepcopy(poison),
                                                           trace_id="noseed-1")),
        },
        "same_server_clean_looking_tool": {
            "seeded_from_chain": summary(fresh2.inspect(copy.deepcopy(benign),
                                                        trace_id="ledger-2")),
            "fresh_without_seed": summary(
                ReputationAirlock(ReputationBook(), policy=HARNESS_POLICY).inspect(
                    copy.deepcopy(benign), trace_id="noseed-2")),
        },
    }
    for key, pair in (("poisoned", ledger["poisoned_request"]),
                      ("clean-looking", ledger["same_server_clean_looking_tool"])):
        seeded = pair["seeded_from_chain"]["quarantined_tools"]
        unseeded = pair["fresh_without_seed"]["quarantined_tools"]
        print(f"  {key} calc request: seeded quarantined={seeded} unseeded quarantined={unseeded}")

    finished = now()
    proofs = {
        "network": NETWORK,
        "horizon": "https://horizon-testnet.stellar.org",
        "started_at": started,
        "finished_at": finished,
        "wallets": wallets,
        "traffic": {"rounds": rounds, "scores": snap},
        "bindings": {"server:calc": {"agent_id": 1, "agent_wallet": agents["server:calc"]},
                     "server:weather": {"agent_id": 2,
                                        "agent_wallet": agents["server:weather"]}},
        "attestations": {
            name: {
                "subject": docs[name]["subject"],
                "score": docs[name]["score"],
                "level": docs[name]["evidence"]["level"],
                "file": f"docs/testnet/attestation-{name}.json",
                "doc_hash": doc_hash(docs[name]).hex(),
                "data_key": data_key(docs[name]["agent"]),
                "tx_hash": txs[name],
                "explorer": explorer_tx(txs[name]),
                "ledger": checks[name].get("ledger"),
                "created_at": checks[name].get("created_at"),
                "verification": checks[name],
            }
            for name in docs
        },
        "tamper_test": {"changed": "score -> 95 in a copy of attestation-calc.json (not published)",
                        "ok": tamper["ok"], "checks": tamper["checks"],
                        "doc_hash": tamper["doc_hash_hex"], "memo_hash": tamper["memo_hash_hex"]},
        "reputation_from_ledger": ledger,
    }
    write_json(OUT / "proofs.json", proofs)
    MD.write_text(render_md(proofs), encoding="utf-8")
    print(f"[{finished}] wrote docs/testnet/proofs.json and docs/TESTNET_PROOFS.md")
    ok = (all(c["ok"] for c in checks.values()) and not tamper["ok"]
          and POISONED in ledger["poisoned_request"]["seeded_from_chain"]["quarantined_tools"])
    return 0 if ok else 1


def yes(flag: bool) -> str:
    return "yes" if flag else "no"


def render_md(p: dict[str, Any]) -> str:
    lines = [
        "# Testnet proofs: Airlock reputation anchored on Stellar",
        "",
        "Generated by `scripts/testnet_attest.py`. Machine readable copy: "
        "[testnet/proofs.json](testnet/proofs.json).",
        "",
        f"- Network: **Stellar TESTNET** (`{p['network']}`), Horizon `{p['horizon']}`."
        " No mainnet, no real funds.",
        f"- Run started {p['started_at']}, finished {p['finished_at']} (UTC).",
        "",
        "## What was tested",
        "",
        "1. Three testnet wallets: an Airlock operator and two MCP servers"
        " (an honest weather server and a calc server that ships a poisoned tool).",
        "2. A `ReputationAirlock` with `HARNESS_POLICY` inspected the demo request"
        " `demo/requests/02_mcp_poisoning.json` (tool order varied per round) and clean"
        " requests with `mcp__weather__get_forecast` until the calc server was blocked.",
        "3. Each server subject was bound to a local agent id, turned into an attestation"
        " document (ERC-8004 feedback shape) and its sha256 was anchored in one testnet"
        " transaction: a 0.0000001 XLM payment operator -> agent wallet with `Memo hash`"
        " = document hash, plus a `ManageData` entry `airlock:rep:<agent[:8]>` on the"
        " operator account holding the same 32 bytes.",
        "4. Both transactions were re-read from Horizon and checked against the documents.",
        "5. A tampered copy was rejected; a fresh Airlock inherited reputation from the ledger.",
        "",
        "## Wallets",
        "",
        "| Role | Public key | Explorer |",
        "| --- | --- | --- |",
    ]
    for role, w in p["wallets"].items():
        lines.append(f"| {role}: {w['role']} | `{w['public_key']}` | [account]({w['explorer']}) |")
    lines += [
        "",
        "## Reputation built from traffic",
        "",
        "| Subject | Score | Level | Incidents |",
        "| --- | --- | --- | --- |",
    ]
    for subject, info in p["traffic"]["scores"].items():
        lines.append(f"| `{subject}` | {info['score']} | {info['level']} | {info['incidents']} |")
    lines += [
        "",
        f"Poisoned requests inspected: {len(p['traffic']['rounds'])}; the poisoned tool was"
        " quarantined from the forwarded request every time.",
        "",
        "## Transactions",
        "",
        "| Subject | Agent id | Score | Document | Document sha256 | Transaction |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for name, a in p["attestations"].items():
        agent_id = p["bindings"][a["subject"]]["agent_id"]
        lines.append(
            f"| `{a['subject']}` | {agent_id} | {a['score']} ({a['level']}) |"
            f" [attestation-{name}.json](testnet/attestation-{name}.json) | `{a['doc_hash']}` |"
            f" [{a['tx_hash'][:16]}...]({a['explorer']}) |"
        )
    lines += [
        "",
        "## Verification from Horizon",
        "",
        "| Subject | ok | successful | source is operator | memo is doc hash |"
        " payment to agent | data entry is doc hash | evidence hash | ledger | closed at |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for a in p["attestations"].values():
        c = a["verification"]["checks"]
        lines.append(
            f"| `{a['subject']}` | **{yes(a['verification']['ok'])}** | {yes(c['successful'])} |"
            f" {yes(c['source_is_operator'])} | {yes(c['memo_is_doc_hash'])} |"
            f" {yes(c['payment_to_agent'])} | {yes(c['data_entry_is_doc_hash'])} |"
            f" {yes(c['evidence_consistent'])} | {a['ledger']} | {a['created_at']} |"
        )
    t = p["tamper_test"]
    lines += [
        "",
        "## Tamper test",
        "",
        f"A copy of `attestation-calc.json` with the score changed to 95 (never published)"
        f" was verified against the real calc transaction: ok = **{yes(t['ok'])}**,"
        f" memo is doc hash = {yes(t['checks']['memo_is_doc_hash'])}.",
        f"Tampered document hash `{t['doc_hash']}` differs from the anchored memo"
        f" `{t['memo_hash']}`.",
        "",
        "## Reputation from the ledger",
        "",
        "A FRESH `ReputationBook` + `ReputationAirlock` with no local history called"
        " `seed_from_chain` with three (document, transaction) pairs:",
        "",
        "| Document | Subject | Transaction | Verified | Seeded | Failed checks |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    ledger = p["reputation_from_ledger"]
    for r in ledger["seed_reports"]:
        failed = ", ".join(r["failed_checks"]) or "none"
        lines.append(f"| {r['document']} | `{r['subject']}` | `{r['tx_hash'][:16]}...` |"
                     f" {yes(r['ok'])} | {yes(r['seeded'])} | {failed} |")
    lines += ["", "Scores in the fresh instance after seeding:", ""]
    for subject, info in ledger["fresh_scores"].items():
        lines.append(f"- `{subject}`: {info['score']} ({info['level']}, source {info['source']})")
    lines += [
        "",
        "Each row below is the FIRST request seen by its own fresh instance (seeded from the"
        " ledger, or with no seed at all). The clean-looking request is the same calc server"
        " shipping `mcp__calc__add_numbers` with only its benign first sentence as description:"
        " content detectors find nothing, so only the on-chain reputation can stop it.",
        "",
        "| Request | Instance | Quarantined tools | Reputation flag | Rules |",
        "| --- | --- | --- | --- | --- |",
    ]
    cases = (("02_mcp_poisoning.json", "poisoned_request"),
             ("same calc server, clean-looking add_numbers", "same_server_clean_looking_tool"))
    for label, key in cases:
        for inst, name in (("seeded from chain", "seeded_from_chain"),
                           ("fresh, no seed", "fresh_without_seed")):
            s = ledger[key][name]
            quarantined = ", ".join(f"`{q}`" for q in s["quarantined_tools"]) or "none"
            rules = ", ".join(s["rules"]) or "none"
            lines.append(f"| {label} | {inst} | {quarantined} | {yes(s['reputation_flag'])} |"
                         f" {rules} |")
    lines += [
        "",
        "## Limitations",
        "",
        "- Testnet only. Testnet is reset periodically, so these links can disappear after a"
        " reset; `proofs.json` and the attestation files keep the hashes.",
        "- The ERC-8004 feedback SHAPE is anchored on Stellar; nothing is written to the"
        " official ERC-8004 EVM registries.",
        "- Agent ids (1 = calc, 2 = weather) are local stand-ins for ERC-8004 agentIds. On"
        " Stellar the agent identity is the agent wallet address.",
        "- The chain proves who attested what and when, not that the score is fair: an importer"
        " still decides which operators to trust.",
        "- Operator key custody is out of Airlock's scope: the script reads keys from a file"
        " outside the repo (chmod 600); Airlock itself never stores keys.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
