"""CISA KEV enrichment: fetch/cache the catalog and match CVE mentions.

KEV entries are corroboration metadata, never articles (spec: 'KEV as
enrichment'). Extraction is confident-only: the exact CVE pattern on
normalized text.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

import httpx

from newsroom.config import Config
from newsroom.safety import normalize_text
from newsroom.store import Store

logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cves(text: str) -> list[str]:
    return list(dict.fromkeys(
        m.group(0).upper() for m in CVE_RE.finditer(normalize_text(text))
    ))


def parse_kev_payload(payload: dict) -> list[dict]:
    entries = []
    for record in payload.get("vulnerabilities", []):
        if not isinstance(record, dict) or not record.get("cveID"):
            continue
        entries.append({
            "cve_id": str(record["cveID"]).upper(),
            "vendor": str(record.get("vendorProject", "")),
            "product": str(record.get("product", "")),
            "name": str(record.get("vulnerabilityName", "")),
            "date_added": str(record.get("dateAdded", "")) or None,
            "due_date": str(record.get("dueDate", "")) or None,
            "ransomware_use": str(record.get("knownRansomwareCampaignUse", "")),
        })
    return entries


def refresh_kev(store: Store, config: Config) -> int:
    """Fetch the KEV catalog unless the cache is fresh. Fail-soft to cache."""
    if not config.kev.enabled:
        return 0
    fetched_at = store.get_meta("kev_fetched_at")
    if fetched_at:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(fetched_at)
        if age < timedelta(hours=config.kev.refresh_hours):
            return len(store.kev_ids())
    try:
        response = httpx.get(config.kev.url, timeout=config.kev.timeout_seconds,
                             follow_redirects=True)
        response.raise_for_status()
        entries = parse_kev_payload(response.json())
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("KEV refresh failed, using cached entries: %s", exc)
        return len(store.kev_ids())
    store.upsert_kev(entries)
    store.set_meta("kev_fetched_at", datetime.now(timezone.utc).isoformat())
    return len(entries)


def record_mentions(store: Store, article_id: str, text: str) -> tuple[list[str], bool]:
    """Extract CVEs from text, persist mentions, report KEV corroboration."""
    cves = extract_cves(text)
    if not cves:
        return [], False
    kev_ids = store.kev_ids()
    mentions = {cve: cve in kev_ids for cve in cves}
    store.record_cve_mentions(article_id, mentions)
    return cves, any(mentions.values())
