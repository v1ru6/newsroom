import json
from pathlib import Path

import pytest

from newsroom.ingest.kev import extract_cves, parse_kev_payload, record_mentions
from newsroom.store import Store

FIXTURE = Path(__file__).parent / "fixtures" / "kev_sample.json"


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "n.db")
    yield s
    s.close()


def test_extract_cves_confident_only():
    text = "cve-2026-1234 and CVE-2026-1234 again; CVE-26-1 is not valid; CVE&#45;2026&#45;0007"
    assert extract_cves(text) == ["CVE-2026-1234", "CVE-2026-0007"]


def test_parse_and_upsert_kev(store):
    entries = parse_kev_payload(json.loads(FIXTURE.read_text()))
    assert entries[0]["cve_id"] == "CVE-2026-1234"
    assert entries[0]["due_date"] == "2026-07-22"
    assert entries[1]["due_date"] is None
    store.upsert_kev(entries)
    assert store.kev_ids() == {"CVE-2026-1234", "CVE-2026-0007"}
    assert store.recent_kev(limit=1)[0]["cve_id"] == "CVE-2026-1234"


def test_record_mentions(store):
    store.upsert_kev(parse_kev_payload(json.loads(FIXTURE.read_text())))
    cves, in_kev = record_mentions(store, "a1", "Patch CVE-2026-1234 now")
    assert cves == ["CVE-2026-1234"] and in_kev is True
    cves, in_kev = record_mentions(store, "a2", "Patch CVE-2020-9999 eventually")
    assert cves == ["CVE-2020-9999"] and in_kev is False
