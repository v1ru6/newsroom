"""Watch-loop scheduler test.

This calls the scheduler loop directly with a tiny interval and a controlled
failure to prove one bad run is reported without stopping future runs.
"""

import threading
from newsroom.cli import watch_loop

def test_watch_loop_runs_and_survives_errors():
    calls = []
    errors = []
    stop = threading.Event()

    def run_once():
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("feed exploded")
        if len(calls) >= 3:
            stop.set()

    watch_loop(run_once, interval_seconds=0.01, stop=stop,
               on_error=errors.append)
    assert len(calls) >= 3          # kept running after the error
    assert len(errors) == 1
