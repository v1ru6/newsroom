"""Command-line interface: `newsroom run`, `newsroom serve`, `newsroom watch`."""

from __future__ import annotations

import argparse
import logging
import random
import sys
import threading

from pydantic import ValidationError

from newsroom.config import load_config
from newsroom.workflow import run_workflow


def watch_loop(run_once, interval_seconds: float, stop: threading.Event,
               on_error) -> None:
    """Run the pipeline on an interval; a failed run is an event, not a crash."""
    while not stop.is_set():
        try:
            run_once()
        except Exception as exc:
            on_error(exc)
        jitter = interval_seconds * random.uniform(-0.1, 0.1)
        stop.wait(max(0.001, interval_seconds + jitter))


def _load(args: argparse.Namespace):
    return load_config(
        args.config,
        alert_threshold=args.threshold,
        fixture_path=getattr(args, "fixture", None),
        max_items_per_source=getattr(args, "limit", None),
        output_dir=args.output_dir,
        db_path=args.db_path,
        llm_enabled=True if getattr(args, "llm", False) else None,
        kev_enabled=False if getattr(args, "no_kev", False) else None,
    )


def cmd_run(args: argparse.Namespace) -> int:
    try:
        config = _load(args)
    except ValidationError as exc:
        print(f"error: invalid configuration: {exc}", file=sys.stderr)
        return 2
    report = run_workflow(config)

    print(f"Sources: {', '.join(f'{h.name}={h.status}' for h in report.source_health)}")
    print(
        f"Articles: {report.articles_seen} seen, {report.duplicates_removed} duplicates removed"
    )
    print(
        f"Decisions: {len(report.alerts)} alerts, {len(report.watchlist)} watchlist, "
        f"{len(report.suppressed)} suppressed"
    )
    for alert in report.alerts:
        print(f"  [{alert.severity.upper()}] ({alert.score:.2f}) {alert.title}")
    print(f"Artifacts written to {config.output_dir}/")

    if report.articles_seen == 0:
        print("warning: no articles ingested (all sources failed or empty)", file=sys.stderr)
        return 1
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from newsroom.server import create_server
    from newsroom.store import Store

    store = Store(args.db_path or "output/newsroom.db")
    server = create_server(store, port=args.port)
    print(f"NewsRoom monitor at http://127.0.0.1:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        store.close()
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    from newsroom.server import create_server
    from newsroom.store import Store

    try:
        config = _load(args)
    except ValidationError as exc:
        print(f"error: invalid configuration: {exc}", file=sys.stderr)
        return 2

    store = Store(config.db_path)
    stop = threading.Event()

    def run_once():
        report = run_workflow(config, store=store)
        print(f"run finished: {len(report.alerts)} alerts, "
              f"{report.articles_seen} articles", flush=True)

    def on_error(exc: Exception):
        print(f"run failed: {exc}", file=sys.stderr, flush=True)

    worker = threading.Thread(
        target=watch_loop, args=(run_once, args.interval, stop, on_error),
        daemon=True)
    worker.start()

    server = create_server(store, port=args.port)
    print(f"NewsRoom monitor at http://127.0.0.1:{args.port} "
          f"(pipeline every {args.interval:.0f}s)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        store.close()
    return 0


def _add_run_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", default="config.yaml", help="YAML config path")
    parser.add_argument("--threshold", type=float, default=None, help="Override alert_threshold")
    parser.add_argument("--output-dir", default=None, help="Override output directory")
    parser.add_argument("--db-path", default=None, help="Override SQLite database path")
    parser.add_argument("--llm", action="store_true", help="Enable optional LLM path from config")
    parser.add_argument("--no-kev", action="store_true", help="Disable CISA KEV enrichment")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="newsroom", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run the ingest-classify-alert workflow")
    _add_run_flags(run_parser)
    run_parser.add_argument("--fixture", default=None, help="Use a local RSS file instead of live feeds")
    run_parser.add_argument("--limit", type=int, default=None, help="Override max_items_per_source")
    run_parser.set_defaults(func=cmd_run)

    serve_parser = subparsers.add_parser("serve", help="Serve the monitor console (no scheduler)")
    serve_parser.add_argument("--db-path", default="output/newsroom.db")
    serve_parser.add_argument("--port", type=int, default=8765)
    serve_parser.set_defaults(func=cmd_serve)

    watch_parser = subparsers.add_parser(
        "watch", help="Run the pipeline on an interval and serve the monitor")
    _add_run_flags(watch_parser)
    watch_parser.add_argument("--interval", type=float, default=900.0,
                              help="Seconds between pipeline runs")
    watch_parser.add_argument("--port", type=int, default=8765)
    watch_parser.set_defaults(func=cmd_watch)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
