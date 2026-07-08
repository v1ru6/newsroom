"""RSS ingestion: fetch live feeds, parse entries, normalize, and dedupe.

This is the first trust boundary. Articles are accepted as attacker-controlled
content, tagged with provenance, and converted into stable normalized items
before any agent or coordinator logic can use them.
"""

from __future__ import annotations
import html
import logging
from datetime import datetime, timezone
from pathlib import Path
from time import mktime
import feedparser
import httpx
from newsroom.config import Config, SourceConfig
from newsroom.models import NewsArticle, NormalizedItem, SourceHealth, normalize_title, stable_id

logger = logging.getLogger(__name__)

def _entry_datetime(entry) -> datetime | None:
    for attr in ("published_parsed", "updated_parsed"):
        parsed = getattr(entry, attr, None)
        if parsed:
            return datetime.fromtimestamp(mktime(parsed), tz=timezone.utc)
    return None

def _source_id(source: SourceConfig | None, source_name: str) -> str:
    return (source.source_id if source and source.source_id else source_name).lower()

def _clean(value: object) -> str:
    return html.unescape(str(value or "")).strip()

def normalize_entries(
    parsed, source_name: str, limit: int, source: SourceConfig | None = None
) -> list[NewsArticle]:
    articles = []
    for entry in parsed.entries[:limit]:
        url = _clean(getattr(entry, "link", ""))
        title = _clean(getattr(entry, "title", ""))
        if not url or not title:
            continue
        articles.append(
            NewsArticle(
                id=stable_id(url),
                title=title,
                summary=_clean(getattr(entry, "summary", "")),
                source=source_name,
                source_id=_source_id(source, source_name),
                source_type=source.type if source else "rss",
                trust_level=source.trust_level if source else "medium",
                url=url,
                published_at=_entry_datetime(entry),
                authors=[a.get("name", "") for a in getattr(entry, "authors", []) if a.get("name")],
                tags=[t.get("term", "") for t in getattr(entry, "tags", []) if t.get("term")],
                focus_tags=source.focus_tags if source else [],
            )
        )
    return articles

def fetch_source(source: SourceConfig, config: Config) -> tuple[list[NewsArticle], SourceHealth]:
    """Fetch one live RSS source. Failures degrade to an empty list + error health."""
    # Keep source failures isolated so one bad feed does not stall the run.
    try:
        response = httpx.get(
            source.url,
            timeout=config.source_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "newsroom/0.1 (+https://github.com/)"},
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("source %s failed: %s", source.name, exc)
        return [], build_source_health(source, "error", error=str(exc))

    parsed = feedparser.parse(response.content)
    articles = normalize_entries(parsed, source.name, config.max_items_per_source, source)
    status = "ok" if articles else "empty"
    return articles, build_source_health(source, status, items=len(articles), normalized=len(articles))

def build_source_health(
    source: SourceConfig,
    status: str,
    *,
    items: int = 0,
    normalized: int = 0,
    error: str | None = None,
) -> SourceHealth:
    return SourceHealth(
        name=source.name,
        source_id=source.source_id,
        source_type=source.type,
        trust_level=source.trust_level,
        url=source.url,
        status=status,
        items_fetched=items,
        items_normalized=normalized,
        error=error,
    )

def load_fixture(path: Path, config: Config) -> tuple[list[NewsArticle], SourceHealth]:
    """Parse a local RSS file instead of the network (demo/test mode)."""
    parsed = feedparser.parse(path.read_bytes())
    articles = normalize_entries(parsed, "fixture", config.max_items_per_source)
    return articles, SourceHealth(
        name="fixture",
        source_id="fixture",
        url=str(path),
        status="fixture",
        items_fetched=len(articles),
        items_normalized=len(articles),
    )

def fetch_all(config: Config) -> tuple[list[NewsArticle], list[SourceHealth]]:
    """Fetch fixture if configured, otherwise all enabled live sources."""
    if config.fixture_path:
        articles, health = load_fixture(Path(config.fixture_path), config)
        return articles, [health]

    all_articles: list[NewsArticle] = []
    health: list[SourceHealth] = []
    for source in config.sources:
        if not source.enabled:
            health.append(build_source_health(source, "disabled"))
            continue
        articles, source_health = fetch_source(source, config)
        all_articles.extend(articles)
        health.append(source_health)
    return all_articles, health

def dedupe(articles: list[NewsArticle]) -> tuple[list[NewsArticle], int]:
    """Drop exact URL duplicates and near-duplicate titles. Keeps first seen."""
    seen_urls: set[str] = set()
    seen_titles: set[str] = set()
    unique: list[NewsArticle] = []
    for article in articles:
        url_key, title_key = article.dedupe_keys
        if url_key in seen_urls or title_key in seen_titles:
            continue
        seen_urls.add(url_key)
        seen_titles.add(title_key)
        unique.append(article)
    return unique, len(articles) - len(unique)

def articles_to_normalized_items(articles: list[NewsArticle]) -> list[NormalizedItem]:
    items: list[NormalizedItem] = []
    for article in articles:
        source_id = article.source_id or article.source.lower().replace(" ", "-")
        canonical_url = article.url.rstrip("/")
        normalized = normalize_title(article.title)
        untrusted_text = article.text
        text_hash = stable_id(normalized, untrusted_text)
        # Preserve provenance and a stable hash before any scoring touches the item.
        items.append(
            NormalizedItem(
                id=stable_id(canonical_url, text_hash),
                article_id=article.id,
                title=article.title,
                source=article.source,
                source_id=source_id,
                source_type=article.source_type,
                trust_level=article.trust_level,
                canonical_url=canonical_url,
                normalized_title=normalized,
                untrusted_text=untrusted_text,
                text_hash=text_hash,
                published_at=article.published_at,
                focus_tags=article.focus_tags,
                provenance={
                    "article_id": article.id,
                    "source": article.source,
                    "source_id": source_id,
                    "url": article.url,
                },
            )
        )
    return items


def dedupe_items(items: list[NormalizedItem]) -> tuple[list[NormalizedItem], int]:
    seen_urls: set[str] = set()
    seen_titles: set[str] = set()
    seen_hashes: set[str] = set()
    unique: list[NormalizedItem] = []
    for item in items:
        url_key, title_key, hash_key = item.dedupe_keys
        if url_key in seen_urls or title_key in seen_titles or hash_key in seen_hashes:
            continue
        seen_urls.add(url_key)
        seen_titles.add(title_key)
        seen_hashes.add(hash_key)
        unique.append(item)
    return unique, len(items) - len(unique)
