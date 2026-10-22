"""Offline tests for airlock.attest: no network, Horizon is faked."""

from __future__ import annotations

import base64
import copy

import pytest

from airlock import attest
from airlock.attest import (
    attestation_document,
    canonical_json,
    data_key,
    doc_hash,
    seed_from_chain,
    verify,
)
from airlock.reputation import ReputationBook

OPERATOR = "GOPERATOR0000000000000000000000000000000000000000000000"
AGENT = "GAGENT00000000000000000000000000000000000000000000000000"


def make_doc(score: int = 10) -> dict:
    book = ReputationBook(clock=lambda: 1_700_000_000.0)
    book.seed([{"subject": "server:calc", "score": score}])
    book.bind("server:calc", 1)
    return attestation_document(book, "server:calc", OPERATOR, AGENT, audit_head="ab" * 32)


def fake_horizon(doc: dict, **overrides) -> dict:
    digest = doc_hash(doc)
    tx = {
        "successful": True,
        "source_account": doc["operator"],
        "memo_type": "hash",
        "memo": base64.b64encode(digest).decode("ascii"),
        "ledger": 123,
        "created_at": "2026-10-22T18:00:00Z",
    }
    tx.update(overrides)
    ops = [
        {"type": "payment", "to": doc["agent"], "asset_type": "native", "amount": "0.0000001"},
        {"type": "manage_data", "name": data_key(doc["agent"]),
         "value": base64.b64encode(digest).decode("ascii")},
    ]
    return {"tx": tx, "operations": ops}


def install(monkeypatch, responses: dict) -> None:
    def fetch(tx_hash, horizon=attest.HORIZON):
        return responses[tx_hash]

    monkeypatch.setattr(attest, "fetch_transaction", fetch)


def test_canonical_json_is_stable_and_ascii():
    a = {"b": 1, "a": {"y": [1, 2], "x": "café"}}
    b = {"a": {"x": "café", "y": [1, 2]}, "b": 1}
    assert canonical_json(a) == canonical_json(b)
    assert canonical_json(a) == '{"a":{"x":"caf\\u00e9","y":[1,2]},"b":1}'


def test_doc_hash_is_deterministic_32_bytes():
    doc = make_doc()
    assert doc_hash(doc) == doc_hash(copy.deepcopy(doc))
    assert len(doc_hash(doc)) == 32
    changed = copy.deepcopy(doc)
    changed["score"] = 95
    assert doc_hash(changed) != doc_hash(doc)


def test_attestation_document_fields():
    doc = make_doc(score=10)
    assert doc["network"] == "stellar:testnet"
    assert doc["operator"] == OPERATOR and doc["agent"] == AGENT
    assert doc["audit_head"] == "ab" * 32
    assert doc["schema"] == "airlock.reputation.v1 (ERC-8004 feedback shape)"
    assert doc["subject"] == "server:calc"
    assert doc["agentId"] == 1 and doc["score"] == 10
    assert doc["evidence"]["level"] == "blocked"
    assert attest.evidence_consistent(doc)
    assert data_key(AGENT) == "airlock:rep:GAGENT00"


def test_attestation_requires_binding():
    book = ReputationBook()
    with pytest.raises(LookupError):
        attestation_document(book, "server:calc", OPERATOR, AGENT)


def test_verify_accepts_matching_transaction(monkeypatch):
    doc = make_doc()
    install(monkeypatch, {"tx1": fake_horizon(doc)})
    result = verify("tx1", doc)
    assert result["ok"] is True
    assert all(result["checks"].values())
    assert result["memo_hash_hex"] == doc_hash(doc).hex()


def test_verify_rejects_tampered_document(monkeypatch):
    doc = make_doc()
    install(monkeypatch, {"tx1": fake_horizon(doc)})
    tampered = copy.deepcopy(doc)
    tampered["score"] = 95
    result = verify("tx1", tampered)
    assert result["ok"] is False
    assert result["checks"]["memo_is_doc_hash"] is False


@pytest.mark.parametrize(
    "overrides, failed",
    [
        ({"successful": False}, "successful"),
        ({"source_account": "GSOMEONEELSE"}, "source_is_operator"),
        ({"memo_type": "text"}, "memo_is_doc_hash"),
        ({"memo": "not base64!"}, "memo_is_doc_hash"),
    ],
)
def test_verify_checks_each_field(monkeypatch, overrides, failed):
    doc = make_doc()
    install(monkeypatch, {"tx1": fake_horizon(doc, **overrides)})
    result = verify("tx1", doc)
    assert result["ok"] is False
    assert result["checks"][failed] is False


def test_verify_requires_payment_to_agent(monkeypatch):
    doc = make_doc()
    response = fake_horizon(doc)
    response["operations"][0]["to"] = "GSOMEONEELSE"
    install(monkeypatch, {"tx1": response})
    result = verify("tx1", doc)
    assert result["ok"] is False and result["checks"]["payment_to_agent"] is False


def test_verify_reports_network_errors(monkeypatch):
    def broken(tx_hash, horizon=attest.HORIZON):
        raise OSError("offline")

    monkeypatch.setattr(attest, "fetch_transaction", broken)
    result = verify("tx1", make_doc())
    assert result["ok"] is False and "offline" in result["error"]


def test_seed_from_chain_seeds_verified_and_rejects_tampered(monkeypatch):
    doc = make_doc(score=3)
    tampered = copy.deepcopy(doc)
    tampered["score"] = 95
    install(monkeypatch, {"tx1": fake_horizon(doc)})
    book = ReputationBook()
    reports = seed_from_chain(book, [(tampered, "tx1"), (doc, "tx1")])
    assert [r["seeded"] for r in reports] == [False, True]
    assert book.score("server:calc") == 3
    assert book.level("server:calc") == "blocked"
    assert book.snapshot()["server:calc"]["agent_id"] == 1


def test_seed_from_chain_rejects_everything_unverified(monkeypatch):
    doc = make_doc(score=3)
    tampered = copy.deepcopy(doc)
    tampered["score"] = 95
    install(monkeypatch, {"tx1": fake_horizon(doc)})
    book = ReputationBook()
    reports = seed_from_chain(book, [(tampered, "tx1")])
    assert reports[0]["ok"] is False and reports[0]["seeded"] is False
    assert book.score("server:calc") == book.prior
    assert book.snapshot() == {}
