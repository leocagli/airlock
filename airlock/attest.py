"""On-chain proofs for Airlock reputation, anchored on the Stellar TESTNET.

An attestation document is the ERC-8004 feedback entry that ReputationBook
already builds (erc8004_feedback), plus who signed it (operator wallet), who
it is about (agent wallet) and an optional audit chain head. Its sha256 over
canonical JSON is anchored in one Stellar transaction:

- a Payment of the minimum amount (0.0000001 XLM, testnet, valueless) from
  the operator to the agent wallet, with Memo hash = doc_hash(doc);
- a ManageData entry on the operator account, key "airlock:rep:<agent[:8]>",
  value = the same 32-byte hash (the latest attestation per agent).

verify() re-reads the transaction from Horizon and checks it matches the
document, so any operator can import another operator's reputation with
seed_from_chain() and reject tampered or unanchored documents.

Scope: TESTNET only. On Stellar the agent identity is the agent wallet
address; the integer agentId is a local stand-in for an ERC-8004 agentId.
Airlock never stores keys: publish() receives a keypair from the caller.

The core (documents, hashing, verification logic) is standard library only.
stellar_sdk is imported lazily, only by publish().
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.error
import urllib.request
from collections.abc import Iterable
from typing import Any

from .reputation import ReputationBook, _canonical

NETWORK = "stellar:testnet"
HORIZON = "https://horizon-testnet.stellar.org"
EXPLORER = "https://stellar.expert/explorer/testnet"
SCHEMA = "airlock.reputation.v1 (ERC-8004 feedback shape)"
MIN_AMOUNT = "0.0000001"
DATA_KEY_PREFIX = "airlock:rep:"
TIMEOUT_S = 30


class StellarSDKMissingError(ImportError):
    """publish() needs the optional dependency: pip install 'airlock[stellar]'."""


# --- documents --------------------------------------------------------------


def canonical_json(doc: Any) -> str:
    """Stable serialization: sorted keys, no whitespace, ASCII only."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def doc_hash(doc: Any) -> bytes:
    """sha256 of canonical_json(doc): 32 bytes, the value anchored on chain."""
    return hashlib.sha256(canonical_json(doc).encode("utf-8")).digest()


def data_key(agent_address: str) -> str:
    """ManageData key on the operator account for one agent (max 64 bytes)."""
    return f"{DATA_KEY_PREFIX}{agent_address[:8]}"


def attestation_document(
    book: ReputationBook,
    subject: str,
    operator: str,
    agent_address: str,
    audit_head: str | None = None,
) -> dict[str, Any]:
    """ERC-8004 feedback for a bound subject, plus the Stellar parties and audit head."""
    doc = book.erc8004_feedback(subject)
    doc.update({
        "subject": subject,
        "network": NETWORK,
        "operator": operator,
        "agent": agent_address,
        "audit_head": audit_head,
        "schema": SCHEMA,
    })
    return doc


def evidence_consistent(doc: dict[str, Any]) -> bool:
    """The filehash inside the feedback matches its embedded evidence."""
    evidence = doc.get("evidence")
    if not isinstance(evidence, dict):
        return False
    digest = hashlib.sha256(_canonical(evidence).encode("utf-8")).hexdigest()
    return digest == doc.get("filehash")


# --- network ----------------------------------------------------------------


MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def _get_json(url: str) -> dict[str, Any]:
    # Only https: a configurable Horizon URL must never become file:// or ftp://.
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL: {url!r}")
    req = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": "airlock-attest/0.1"}
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:  # nosec B310 - https only
        raw = resp.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("Horizon response larger than 2 MB")
    return json.loads(raw.decode("utf-8"))


def fetch_transaction(tx_hash: str, horizon: str = HORIZON) -> dict[str, Any]:
    """Transaction record and its operations from Horizon: {"tx": {...}, "operations": [...]}."""
    tx = _get_json(f"{horizon}/transactions/{tx_hash}")
    ops = _get_json(f"{horizon}/transactions/{tx_hash}/operations?limit=50")
    records = ops.get("_embedded", {}).get("records", [])
    return {"tx": tx, "operations": records}


def account_exists(address: str, horizon: str = HORIZON) -> bool:
    try:
        _get_json(f"{horizon}/accounts/{address}")
        return True
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise


def friendbot(address: str) -> None:
    """Fund a new TESTNET account (Friendbot exists only on test networks)."""
    _get_json(f"https://friendbot.stellar.org/?addr={address}")


def _sdk() -> Any:
    try:
        import stellar_sdk
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise StellarSDKMissingError(
            "stellar-sdk is not installed: pip install 'airlock[stellar]'"
        ) from exc
    return stellar_sdk


def publish(operator_keypair: Any, agent_address: str, doc: dict[str, Any]) -> str:
    """Anchor doc_hash(doc) on the Stellar TESTNET. Returns the transaction hash."""
    sdk = _sdk()
    if operator_keypair.public_key != doc.get("operator"):
        raise ValueError("the signing keypair is not the document's operator")
    if agent_address != doc.get("agent"):
        raise ValueError("agent_address does not match the document's agent")
    digest = doc_hash(doc)
    server = sdk.Server(horizon_url=HORIZON)
    account = server.load_account(operator_keypair.public_key)
    tx = (
        sdk.TransactionBuilder(
            source_account=account,
            network_passphrase=sdk.Network.TESTNET_NETWORK_PASSPHRASE,
            base_fee=server.fetch_base_fee(),
        )
        .append_payment_op(destination=agent_address, asset=sdk.Asset.native(), amount=MIN_AMOUNT)
        .append_manage_data_op(data_name=data_key(agent_address), data_value=digest)
        .add_hash_memo(digest)
        .set_timeout(120)
        .build()
    )
    tx.sign(operator_keypair)
    response = server.submit_transaction(tx)
    return str(response["hash"])


# --- verification -----------------------------------------------------------


def verify(tx_hash: str, doc: dict[str, Any]) -> dict[str, Any]:
    """Check on Horizon that tx_hash anchors exactly this document."""
    checks = {
        "found": False,
        "successful": False,
        "source_is_operator": False,
        "memo_is_doc_hash": False,
        "payment_to_agent": False,
        "data_entry_is_doc_hash": False,
        "evidence_consistent": evidence_consistent(doc),
    }
    result: dict[str, Any] = {"ok": False, "tx_hash": tx_hash, "checks": checks}
    try:
        fetched = fetch_transaction(tx_hash)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    tx = fetched.get("tx") or {}
    ops = fetched.get("operations") or []
    checks["found"] = bool(tx)
    checks["successful"] = tx.get("successful") is True
    checks["source_is_operator"] = tx.get("source_account") == doc.get("operator")
    expected = doc_hash(doc)
    memo = tx.get("memo")
    try:
        memo_bytes = base64.b64decode(memo, validate=True) if isinstance(memo, str) else b""
    except ValueError:
        memo_bytes = b""
    checks["memo_is_doc_hash"] = tx.get("memo_type") == "hash" and memo_bytes == expected
    agent = doc.get("agent")
    checks["payment_to_agent"] = any(
        op.get("type") == "payment"
        and op.get("to") == agent
        and op.get("asset_type") == "native"
        for op in ops
    )
    key = data_key(agent) if isinstance(agent, str) else None
    expected_b64 = base64.b64encode(expected).decode("ascii")
    checks["data_entry_is_doc_hash"] = any(
        op.get("type") == "manage_data"
        and op.get("name") == key
        and op.get("value") == expected_b64
        for op in ops
    )
    result["ledger"] = tx.get("ledger")
    result["created_at"] = tx.get("created_at")
    result["memo_hash_hex"] = memo_bytes.hex() if memo_bytes else None
    result["doc_hash_hex"] = expected.hex()
    result["ok"] = all(checks.values())
    return result


def seed_from_chain(
    book: ReputationBook,
    docs_and_txs: Iterable[tuple[dict[str, Any], str]],
) -> list[dict[str, Any]]:
    """Seed a book only with documents whose anchor verifies on chain.

    Returns one report per pair: {"subject", "tx_hash", "ok", "seeded", "verify"}.
    Unverified or tampered documents are rejected and never reach book.seed().
    """
    reports: list[dict[str, Any]] = []
    accepted: list[dict[str, Any]] = []
    for doc, tx_hash in docs_and_txs:
        subject = doc.get("subject") or (doc.get("evidence") or {}).get("subject")
        check = verify(tx_hash, doc)
        report = {"subject": subject, "tx_hash": tx_hash, "ok": check["ok"], "seeded": False,
                  "verify": check}
        if check["ok"] and isinstance(subject, str):
            accepted.append({
                "subject": subject,
                "score": doc.get("score"),
                "agent_id": doc.get("agentId"),
                "registry": f"{NETWORK}:{doc.get('agent')}",
                "source": NETWORK,
            })
            report["seeded"] = True
        reports.append(report)
    if accepted:
        book.seed(accepted)
    return reports


def explorer_tx(tx_hash: str) -> str:
    return f"{EXPLORER}/tx/{tx_hash}"


def explorer_account(address: str) -> str:
    return f"{EXPLORER}/account/{address}"
