import json
import threading

from airlock.audit import GENESIS, AuditLog, compute_hash, verify


def _lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def test_chain_links_records(tmp_path):
    path = tmp_path / "nested" / "dir" / "audit.jsonl"
    log = AuditLog(str(path))
    first = log.append({"action": "ALLOW", "trace_id": "a"})
    second = log.append({"action": "BLOCK", "trace_id": "b"})

    assert path.exists()
    assert first["seq"] == 0 and second["seq"] == 1
    assert first["prev_hash"] == GENESIS
    assert second["prev_hash"] == first["hash"]
    assert first["ts"].endswith("Z")
    assert second["hash"] == compute_hash(first["hash"], second)
    assert verify(str(path)) == (True, 2, None)
    assert log.verify() == (True, 2, None)


def test_reserved_fields_cannot_be_spoofed(tmp_path):
    log = AuditLog(str(tmp_path / "a.jsonl"))
    entry = log.append({"seq": 99, "hash": "x", "prev_hash": "y", "action": "WARN"})
    assert entry["seq"] == 0 and entry["prev_hash"] == GENESIS and entry["hash"] != "x"
    assert verify(str(tmp_path / "a.jsonl"))[0]


def test_tampered_record_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    for i in range(5):
        log.append({"action": "BLOCK", "i": i})
    lines = _lines(path)
    rec = json.loads(lines[2])
    rec["action"] = "ALLOW"
    lines[2] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify(str(path)) == (False, 2, 2)


def test_deleted_record_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    for i in range(4):
        log.append({"i": i})
    lines = _lines(path)
    del lines[1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, checked, bad = verify(str(path))
    assert not ok and checked == 1 and bad == 1


def test_garbage_line_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(str(path)).append({"i": 0})
    with path.open("a", encoding="utf-8") as fh:
        fh.write("not json\n")
    assert verify(str(path)) == (False, 1, 1)


def test_recovery_across_instances(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    a = AuditLog(path)
    a.append({"i": 0})
    last = a.append({"i": 1})
    b = AuditLog(path)
    nxt = b.append({"i": 2})
    assert nxt["seq"] == 2
    assert nxt["prev_hash"] == last["hash"]
    assert verify(path) == (True, 3, None)


def test_missing_file_is_empty_valid_chain(tmp_path):
    assert verify(str(tmp_path / "nope.jsonl")) == (True, 0, None)


def test_concurrent_appends_keep_chain_valid(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)

    def worker(n):
        for i in range(25):
            log.append({"worker": n, "i": i})

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert verify(path) == (True, 200, None)
