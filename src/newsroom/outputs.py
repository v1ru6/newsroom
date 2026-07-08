"""File artifact writers for offline review and static console fallback.

The monitor UI lives in real static files (web/). This module exports JSONL,
Markdown, manifest, safety report, and data.json artifacts so a run remains
auditable even without the SQLite API server.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from newsroom.models import ArticleDecision, RunReport, stable_id
from newsroom.safety import redact_untrusted_text

WEB_DIR = Path(__file__).parent / "web"


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w") as fh:
        for row in rows:
            fh.write(json.dumps(row, default=str, sort_keys=True) + "\n")


def write_outputs(report: RunReport, decisions: list[ArticleDecision], output_dir: Path,
                  kev_articles: set[str] | None = None) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    _write_jsonl(
        output_dir / "alerts.jsonl",
        [alert.model_dump(mode="json") for alert in report.alerts],
    )
    _write_jsonl(
        output_dir / "decisions.jsonl",
        [_safe_decision_dict(decision) for decision in decisions],
    )
    _write_jsonl(
        output_dir / "evidence_ledger.jsonl",
        [entry.model_dump(mode="json") for entry in report.evidence_ledger],
    )
    _write_jsonl(
        output_dir / "agent_trace.jsonl",
        [entry.model_dump(mode="json") for entry in report.agent_trace],
    )
    (output_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "started_at": report.started_at,
                "finished_at": report.finished_at,
                "config": report.config_used,
                "source_health": [h.model_dump(mode="json") for h in report.source_health],
                "counts": {
                    "articles_seen": report.articles_seen,
                    "duplicates_removed": report.duplicates_removed,
                    "alerts": len(report.alerts),
                    "watchlist": len(report.watchlist),
                    "suppressed": len(report.suppressed),
                    "ledger_entries": len(report.evidence_ledger),
                    "gate_decisions": len(report.safety_report.gate_decisions),
                },
                "safety_counts": report.safety_report.counts,
                "llm_enabled": report.safety_report.llm_enabled,
                "errors": report.errors,
            },
            default=str,
            indent=2,
            sort_keys=True,
        )
    )
    (output_dir / "safety_report.json").write_text(
        json.dumps(report.safety_report.model_dump(mode="json"), indent=2, sort_keys=True)
    )
    (output_dir / "run_report.md").write_text(render_markdown(report))
    (output_dir / "data.json").write_text(
        json.dumps(build_data_payload(report, decisions, kev_articles),
                   default=str, indent=2))
    for asset in WEB_DIR.iterdir():
        if asset.is_file():
            shutil.copy2(asset, output_dir / asset.name)


def build_data_payload(report: RunReport, decisions: list[ArticleDecision],
                       kev_articles: set[str] | None = None) -> dict:
    """The static console's data feed. Mirrored later by /api/summary."""
    kev_articles = kev_articles or set()
    return {
        "generated_at": (report.finished_at or report.started_at).isoformat(),
        "threshold": report.config_used.get("alert_threshold"),
        "counts": {
            "alerts": len(report.alerts),
            "watchlist": len(report.watchlist),
            "suppressed": len(report.suppressed),
            "articles_seen": report.articles_seen,
            "duplicates_removed": report.duplicates_removed,
        },
        "alerts": [{
            "alert_id": a.alert_id,
            "title": redact_untrusted_text(a.title),
            "severity": a.severity,
            "score": a.score,
            "source": a.source,
            "url": a.source_url,
            "why": redact_untrusted_text(a.why_it_matters),
            "evidence": [redact_untrusted_text(e) for e in a.evidence],
            "safety_notes": [redact_untrusted_text(value) for value in a.safety_notes],
            "first_alerted_at": a.created_at.isoformat(),
            "kev": stable_id(a.source_url) in kev_articles,
        } for a in report.alerts],
        "watchlist": [{
            "title": redact_untrusted_text(d.article.title),
            "score": d.average_score,
            "threshold": d.threshold,
            "source": d.article.source,
            "url": d.article.url,
            "gate_status": d.gate_status,
            "safety_notes": [redact_untrusted_text(value) for value in d.safety_notes],
            "results": [_safe_result_dict(result.model_dump(mode="json"))
                        for result in d.results],
        } for d in report.watchlist],
        "decisions": [{
            "title": redact_untrusted_text(d.article.title),
            "score": d.average_score,
            "decision": d.decision,
            "source": d.article.source,
            "url": d.article.url,
            "reason": d.suppression_reason,
        } for d in decisions],
        "sources": [{
            "source_id": h.source_id or h.name,
            "status": h.status,
            "items": h.items_fetched,
            "error": h.error,
        } for h in report.source_health],
        "errors": report.errors,
    }


def _safe_decision_dict(decision: ArticleDecision) -> dict:
    data = decision.model_dump(mode="json")
    data["article"]["title"] = redact_untrusted_text(data["article"].get("title", ""))
    data["article"]["summary"] = redact_untrusted_text(data["article"].get("summary", ""))
    for result in data.get("results", []):
        _safe_result_dict(result)
    data["safety_notes"] = [redact_untrusted_text(value) for value in data.get("safety_notes", [])]
    return data


def _safe_result_dict(result: dict) -> dict:
    result["reasons"] = [redact_untrusted_text(value) for value in result.get("reasons", [])]
    result["evidence"] = [redact_untrusted_text(value) for value in result.get("evidence", [])]
    return result


def render_markdown(report: RunReport) -> str:
    lines = [
        "# NewsRoom Run Report",
        "",
        f"- Started: {report.started_at:%Y-%m-%d %H:%M:%S %Z}",
        f"- Articles seen: {report.articles_seen} (duplicates removed: {report.duplicates_removed})",
        f"- Alerts: {len(report.alerts)} | Watchlist: {len(report.watchlist)} | Suppressed: {len(report.suppressed)}",
        f"- Ledger entries: {len(report.evidence_ledger)} | Gate decisions: {len(report.safety_report.gate_decisions)}",
        "",
        "## Source Health",
        "",
        "| Source | Status | Items | Error |",
        "|---|---|---|---|",
    ]
    for h in report.source_health:
        lines.append(f"| {h.name} | {h.status} | {h.items_fetched} | {h.error or '-'} |")

    lines += ["", "## Threat Alerts", ""]
    if not report.alerts:
        lines.append("No alerts this run.")
    for alert in report.alerts:
        lines += [
            f"### [{alert.severity.upper()}] {alert.title}",
            "",
            f"- Score: {alert.score:.2f}",
            f"- Why it matters: {alert.why_it_matters}",
            f"- Evidence: {', '.join(alert.evidence) or 'n/a'}",
            f"- Gate status: {alert.gate_status}",
            f"- OWASP categories: {', '.join(alert.owasp_categories) or 'none'}",
            f"- Source: {alert.source_url}",
            f"- Recommended action: {alert.recommended_action}",
            "",
        ]

    lines += ["## Watchlist", ""]
    if not report.watchlist:
        lines.append("Empty.")
    for d in report.watchlist:
        title = redact_untrusted_text(d.article.title)
        lines.append(f"- ({d.average_score:.2f}) {title} - {d.article.url}")

    lines += ["", "## Suppressed", ""]
    if not report.suppressed:
        lines.append("Empty.")
    for d in report.suppressed:
        title = redact_untrusted_text(d.article.title)
        lines.append(f"- ({d.average_score:.2f}) {title} - {d.suppression_reason}")

    lines += ["", "## Safety Gates", ""]
    if not report.safety_report.counts:
        lines.append("No gate decisions recorded.")
    else:
        for status, count in sorted(report.safety_report.counts.items()):
            lines.append(f"- {status}: {count}")
    if report.safety_report.llm_blocked_items:
        lines.append(
            "- LLM-blocked items: " + ", ".join(report.safety_report.llm_blocked_items)
        )

    if report.errors:
        lines += ["", "## Errors", ""]
        lines += [f"- {err}" for err in report.errors]

    return "\n".join(lines) + "\n"
