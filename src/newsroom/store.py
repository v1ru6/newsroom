"""SQLite persistence for the monitor's memory and dashboard API.

The store owns cross-run dedupe, source health, alert-once lifecycle, recent
runs, review status, and KEV cache. One connection is guarded by a lock so the
watch scheduler thread and threaded API server can share it safely.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from newsroom.models import ArticleDecision, NewsArticle, SourceHealth, ThreatAlert, stable_id

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(
  run_id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  articles_seen INTEGER NOT NULL DEFAULT 0,
  new_articles INTEGER NOT NULL DEFAULT 0,
  duplicates_removed INTEGER NOT NULL DEFAULT 0,
  alert_count INTEGER NOT NULL DEFAULT 0,
  watch_count INTEGER NOT NULL DEFAULT 0,
  suppressed_count INTEGER NOT NULL DEFAULT 0,
  errors_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS articles(
  article_id TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  source_id TEXT NOT NULL,
  published_at TEXT,
  first_seen_run INTEGER NOT NULL REFERENCES runs(run_id),
  first_seen_at TEXT NOT NULL,
  summary_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decisions(
  decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES runs(run_id),
  article_id TEXT NOT NULL REFERENCES articles(article_id),
  average_score REAL NOT NULL,
  threshold REAL NOT NULL DEFAULT 0.55,
  decision TEXT NOT NULL,
  suppression_reason TEXT,
  results_json TEXT NOT NULL DEFAULT '[]',
  safety_notes_json TEXT NOT NULL DEFAULT '[]',
  gate_status TEXT NOT NULL DEFAULT 'pass',
  decided_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_run ON decisions(run_id);
CREATE TABLE IF NOT EXISTS alerts(
  alert_id TEXT PRIMARY KEY,
  article_id TEXT NOT NULL UNIQUE REFERENCES articles(article_id),
  severity TEXT NOT NULL,
  first_alerted_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  first_score REAL NOT NULL,
  last_score REAL NOT NULL,
  max_score REAL NOT NULL,
  status_changed_at TEXT,
  why_it_matters TEXT NOT NULL DEFAULT '',
  evidence_json TEXT NOT NULL DEFAULT '[]',
  safety_notes_json TEXT NOT NULL DEFAULT '[]',
  review_status TEXT NOT NULL DEFAULT 'auto'
);
CREATE TABLE IF NOT EXISTS alert_events(
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id TEXT NOT NULL REFERENCES alerts(alert_id),
  event_type TEXT NOT NULL,
  score REAL NOT NULL,
  severity TEXT NOT NULL,
  at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS source_health(
  run_id INTEGER NOT NULL REFERENCES runs(run_id),
  source_id TEXT NOT NULL,
  status TEXT NOT NULL,
  items_fetched INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  observed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kev_entries(
  cve_id TEXT PRIMARY KEY,
  vendor TEXT NOT NULL DEFAULT '',
  product TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '',
  date_added TEXT,
  due_date TEXT,
  ransomware_use TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS cve_mentions(
  -- no FK: mentions are recorded during enrichment, before articles persist
  article_id TEXT NOT NULL,
  cve_id TEXT NOT NULL,
  in_kev INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(article_id, cve_id)
);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, db_path: Path | str):
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(_SCHEMA)
        # migrations for DBs created before these columns existed
        for ddl in (
            "ALTER TABLE alerts ADD COLUMN review_status TEXT NOT NULL DEFAULT 'auto'",
            "ALTER TABLE alerts ADD COLUMN safety_notes_json TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE kev_entries ADD COLUMN due_date TEXT",
            "ALTER TABLE decisions ADD COLUMN threshold REAL NOT NULL DEFAULT 0.55",
            "ALTER TABLE decisions ADD COLUMN safety_notes_json TEXT NOT NULL DEFAULT '[]'",
        ):
            try:
                self.conn.execute(ddl)
            except sqlite3.OperationalError:
                pass  # column already present
        self.conn.commit()

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # -- runs -----------------------------------------------------------------
    def begin_run(self, started_at: datetime) -> int:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO runs(started_at) VALUES (?)", (_iso(started_at),)
            )
            self.conn.commit()
            return int(cur.lastrowid)

    def finish_run(self, run_id: int, *, finished_at: datetime,
                   articles_seen: int, new_articles: int, duplicates_removed: int,
                   alert_count: int, watch_count: int, suppressed_count: int,
                   errors: list[str]) -> None:
        with self._lock:
            self.conn.execute(
                """UPDATE runs SET finished_at=?, articles_seen=?, new_articles=?,
                   duplicates_removed=?, alert_count=?, watch_count=?,
                   suppressed_count=?, errors_json=? WHERE run_id=?""",
                (_iso(finished_at), articles_seen, new_articles, duplicates_removed,
                 alert_count, watch_count, suppressed_count,
                 json.dumps(errors), run_id),
            )
            self.conn.commit()

    # -- articles / decisions / health -----------------------------------------
    def known_text_hashes(self) -> dict[str, str]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT article_id, summary_hash FROM articles").fetchall()
        return {row["article_id"]: row["summary_hash"] for row in rows}

    def upsert_article(self, article: NewsArticle, run_id: int, text_hash: str) -> None:
        with self._lock:
            self.conn.execute(
                """INSERT INTO articles(article_id, url, title, summary, source_id,
                     published_at, first_seen_run, first_seen_at, summary_hash)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(article_id) DO UPDATE SET
                     title=excluded.title, summary=excluded.summary,
                     summary_hash=excluded.summary_hash""",
                (article.id, article.url, article.title, article.summary,
                 article.source_id or article.source, _iso(article.published_at),
                 run_id, _now_iso(), text_hash),
            )
            self.conn.commit()

    def record_decision(self, run_id: int, decision: ArticleDecision) -> None:
        with self._lock:
            self.conn.execute(
                """INSERT INTO decisions(run_id, article_id, average_score, threshold,
                     decision, suppression_reason, results_json, safety_notes_json,
                     gate_status, decided_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (run_id, decision.article.id, decision.average_score, decision.threshold,
                 decision.decision,
                 decision.suppression_reason,
                 json.dumps([r.model_dump(mode="json") for r in decision.results]),
                 json.dumps(decision.safety_notes),
                 decision.gate_status, _now_iso()),
            )
            self.conn.commit()

    def record_source_health(self, run_id: int, health: SourceHealth) -> None:
        with self._lock:
            self.conn.execute(
                """INSERT INTO source_health(run_id, source_id, status, items_fetched,
                     error, observed_at) VALUES (?,?,?,?,?,?)""",
                (run_id, health.source_id or health.name, health.status,
                 health.items_fetched, health.error,
                 _iso(health.observed_at) or _now_iso()),
            )
            self.conn.commit()

    # -- alert lifecycle --------------------------------------------------------
    def record_alert(self, alert: ThreatAlert, at: datetime | None = None) -> str:
        ts = _iso(at) or _now_iso()
        article_id = stable_id(alert.source_url)
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM alerts WHERE article_id=?", (article_id,)).fetchone()
            if row is None:
                # First crossing creates the alert; repeats update history only.
                self.conn.execute(
                    """INSERT INTO alerts(alert_id, article_id, severity,
                         first_alerted_at, last_seen_at, first_score, last_score,
                         max_score, why_it_matters, evidence_json, safety_notes_json,
                         review_status)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (alert.alert_id, article_id, alert.severity, ts, ts,
                     alert.score, alert.score, alert.score, alert.why_it_matters,
                     json.dumps(alert.evidence), json.dumps(alert.safety_notes),
                     alert.review_status))
                event = "created"
                self._alert_event(alert.alert_id, event, alert.score, alert.severity, ts)
                self.conn.commit()
                return event

            event = "severity_changed" if alert.severity != row["severity"] else "re_crossed"
            self.conn.execute(
                """UPDATE alerts SET last_seen_at=?, last_score=?,
                     max_score=MAX(max_score, ?), severity=?,
                     status_changed_at=CASE WHEN ?='severity_changed' THEN ?
                                            ELSE status_changed_at END
                   WHERE alert_id=?""",
                (ts, alert.score, alert.score, alert.severity, event, ts,
                 row["alert_id"]))
            self._alert_event(row["alert_id"], event, alert.score, alert.severity, ts)
            self.conn.commit()
            return event

    def _alert_event(self, alert_id: str, event_type: str, score: float,
                     severity: str, at: str) -> None:
        # caller holds the lock
        self.conn.execute(
            "INSERT INTO alert_events(alert_id, event_type, score, severity, at) "
            "VALUES (?,?,?,?,?)", (alert_id, event_type, score, severity, at))

    def recent_alerts(self, limit: int = 50, *, include_fixture: bool = True) -> list[dict]:
        where = "" if include_fixture else "WHERE a.source_id != ?"
        params: list[object] = []
        if not include_fixture:
            params.append("fixture")
        params.append(limit)
        with self._lock:
            rows = self.conn.execute(
                """SELECT al.*, a.url, a.source_id, a.title AS article_title,
                     (SELECT COUNT(*) FROM alert_events e WHERE e.alert_id=al.alert_id)
                     AS event_count,
                     (SELECT d.results_json FROM decisions d
                      WHERE d.article_id=al.article_id
                      ORDER BY d.decision_id DESC LIMIT 1) AS results_json
                   FROM alerts al JOIN articles a ON a.article_id = al.article_id
                   """
                + where
                + " ORDER BY al.last_seen_at DESC LIMIT ?",
                tuple(params),
            ).fetchall()
        return [dict(row) for row in rows]

    def set_alert_review(self, alert_id: str, action: str) -> bool:
        """HITL decision on a pending alert. Returns False if no such alert."""
        if action not in {"approved", "dismissed"}:
            raise ValueError(f"invalid review action: {action}")
        with self._lock:
            cur = self.conn.execute(
                "UPDATE alerts SET review_status=?, status_changed_at=? WHERE alert_id=?",
                (action, _now_iso(), alert_id))
            self.conn.commit()
        return cur.rowcount > 0

    def alert_events(self, alert_id: str) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM alert_events WHERE alert_id=? ORDER BY event_id",
                (alert_id,)).fetchall()
        return [dict(row) for row in rows]

    # -- meta -------------------------------------------------------------------
    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO meta(key, value) VALUES (?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
            self.conn.commit()

    def get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    # -- queries ------------------------------------------------------------------
    def recent_runs(self, limit: int = 20) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM runs ORDER BY run_id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def search_decisions(self, q: str | None = None, decision: str | None = None,
                         limit: int = 100, *, include_fixture: bool = True) -> list[dict]:
        sql = """SELECT d.*, a.title, a.url, a.source_id FROM decisions d
                 JOIN articles a ON a.article_id = d.article_id"""
        clauses, params = [], []
        if not include_fixture:
            clauses.append("a.source_id != ?")
            params.append("fixture")
        if q:
            clauses.append("a.title LIKE ?")
            params.append(f"%{q}%")
        if decision:
            clauses.append("d.decision = ?")
            params.append(decision)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY d.decision_id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    # -- KEV ----------------------------------------------------------------
    def upsert_kev(self, entries: list[dict]) -> None:
        defaults = {"vendor": "", "product": "", "name": "",
                    "date_added": None, "due_date": None, "ransomware_use": ""}
        entries = [{**defaults, **entry} for entry in entries]
        with self._lock:
            self.conn.executemany(
                """INSERT INTO kev_entries(cve_id, vendor, product, name, date_added,
                     due_date, ransomware_use) VALUES (:cve_id,:vendor,:product,:name,
                     :date_added,:due_date,:ransomware_use)
                   ON CONFLICT(cve_id) DO UPDATE SET vendor=excluded.vendor,
                     product=excluded.product, name=excluded.name,
                     date_added=excluded.date_added, due_date=excluded.due_date,
                     ransomware_use=excluded.ransomware_use""", entries)
            self.conn.commit()

    def kev_ids(self) -> set[str]:
        with self._lock:
            rows = self.conn.execute("SELECT cve_id FROM kev_entries").fetchall()
        return {row["cve_id"] for row in rows}

    def recent_kev(self, limit: int = 20) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                """SELECT k.*, EXISTS(SELECT 1 FROM cve_mentions m
                     WHERE m.cve_id = k.cve_id) AS seen_in_stream
                   FROM kev_entries k ORDER BY k.date_added DESC LIMIT ?""",
                (limit,)).fetchall()
        return [dict(row) for row in rows]

    def record_cve_mentions(self, article_id: str, mentions: dict[str, bool]) -> None:
        with self._lock:
            self.conn.executemany(
                """INSERT INTO cve_mentions(article_id, cve_id, in_kev)
                   VALUES (?,?,?)
                   ON CONFLICT(article_id, cve_id) DO UPDATE SET in_kev=excluded.in_kev""",
                [(article_id, cve, int(in_kev)) for cve, in_kev in mentions.items()])
            self.conn.commit()

    def timeline(self, days: int = 7, *, include_fixture: bool = True) -> list[dict]:
        params: list[object] = [f"-{days} days"]
        source_clause = ""
        if not include_fixture:
            source_clause = " AND a.source_id != ?"
            params.append("fixture")
        with self._lock:
            rows = self.conn.execute(
                """SELECT substr(decided_at, 1, 10) AS day,
                     SUM(decision='alert') AS alerts,
                     SUM(decision='watchlist') AS watchlist,
                     SUM(decision='suppressed') AS suppressed,
                     COUNT(*) AS total,
                     ROUND(AVG(average_score), 3) AS avg_score
                   FROM decisions d JOIN articles a ON a.article_id = d.article_id
                   WHERE d.decided_at >= datetime('now', ?)
                   """
                + source_clause
                + " GROUP BY day ORDER BY day",
                tuple(params),
            ).fetchall()
        return [dict(row) for row in rows]

    def summary(self, *, include_fixture: bool = True) -> dict:
        runs = self.recent_runs(limit=1)
        source_clause = "" if include_fixture else " AND a.source_id != ?"
        source_params: list[object] = [] if include_fixture else ["fixture"]
        with self._lock:
            day_scores = self.conn.execute(
                """SELECT AVG(d.average_score) AS avg_score FROM decisions d
                   JOIN articles a ON a.article_id = d.article_id
                   WHERE d.decided_at >= datetime('now', '-1 day')"""
                + source_clause,
                tuple(source_params),
            ).fetchone()
            alert_count = self.conn.execute(
                """SELECT COUNT(*) AS c FROM alerts al
                   JOIN articles a ON a.article_id = al.article_id
                   WHERE (? OR a.source_id != ?)""",
                (include_fixture, "fixture"),
            ).fetchone()["c"]
            article_count = self.conn.execute(
                "SELECT COUNT(*) AS c FROM articles WHERE (? OR source_id != ?)",
                (include_fixture, "fixture"),
            ).fetchone()["c"]
        return {
            "last_run": runs[0] if runs else None,
            "threat_level": round(day_scores["avg_score"] or 0.0, 3),
            "timeline": self.timeline(7, include_fixture=include_fixture),
            "counts": {"alerts": alert_count, "articles": article_count},
        }

    def latest_source_health(self, *, include_fixture: bool = True) -> list[dict]:
        where = "" if include_fixture else "WHERE source_id != ?"
        params: tuple[object, ...] = () if include_fixture else ("fixture",)
        with self._lock:
            rows = self.conn.execute(
                """SELECT sh.* FROM source_health sh
                   JOIN (SELECT source_id, MAX(rowid) AS max_row FROM source_health
                         """
                + where
                + """ GROUP BY source_id) latest
                   ON sh.rowid = latest.max_row ORDER BY sh.source_id""",
                params,
            ).fetchall()
        return [dict(row) for row in rows]
