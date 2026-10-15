"""Isolated tests for the proposed 2PC timeout diagnostic copy."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT
    / "applications"
    / "pgdog"
    / "integration"
    / "two_pc"
    / "crash_recovery.py"
)
MODULE_NAME = f"_pgdog_crash_recovery_diagnostic_{abs(hash(str(SCRIPT)))}"
SPEC = importlib.util.spec_from_file_location(MODULE_NAME, SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ASYNC_PG_STUB = types.ModuleType("asyncpg")


class AsyncpgPostgresError(Exception):
    pass


ASYNC_PG_STUB.PostgresError = AsyncpgPostgresError
ASYNC_PG_STUB.connect = None
RECOVERY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RECOVERY
with patch.dict(sys.modules, {"asyncpg": ASYNC_PG_STUB}):
    SPEC.loader.exec_module(RECOVERY)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, duration: float) -> None:
        self.now += duration


class TwoPcTimeoutDiagnosticTests(unittest.TestCase):
    def run_async(self, coroutine):
        return asyncio.run(coroutine)

    def test_asyncpg_stub_is_not_left_in_global_module_registry(self):
        self.assertIsNot(sys.modules.get("asyncpg"), ASYNC_PG_STUB)

    def test_live_drain_stays_failed_and_observes_only_fixed_shard_counts(self):
        clock = FakeClock()
        calls = []
        stop_calls = []

        async def wait():
            raise RECOVERY.RecoveryTimeoutError({"shard_0": 2, "shard_1": 2})

        async def count():
            calls.append("count")
            return {"shard_0": 0, "shard_1": 0, "unexpected": "omit"}

        async def stop():
            stop_calls.append("stop")

        async def scenario():
            with self.assertRaises(RECOVERY.RecoveryTimeoutError) as raised:
                await RECOVERY.wait_for_recovery_with_diagnostics(
                    wait,
                    count,
                    stop,
                    monotonic=clock.monotonic,
                    sleep=clock.sleep,
                    grace_seconds=5.0,
                    poll_interval=0.1,
                )
            error = raised.exception
            self.assertEqual(error.counts, {"shard_0": 2, "shard_1": 2})
            self.assertEqual(error.diagnostic.status, "drained_while_running")
            self.assertEqual(error.diagnostic.observations, ({"shard_0": 0, "shard_1": 0},))
            self.assertEqual(error.diagnostic.after_shutdown, {"shard_0": 0, "shard_1": 0})

        self.run_async(scenario())
        self.assertEqual(len(calls), 2)  # One live observation and one post-stop count.
        self.assertEqual(stop_calls, ["stop"])
        self.assertLessEqual(clock.now, 5.0)

    def test_shutdown_clear_and_residue_are_distinguished_after_bounded_grace(self):
        for shutdown_counts, expected in (
            ({"shard_0": 0, "shard_1": 0}, "cleared_after_shutdown"),
            ({"shard_0": 1, "shard_1": 0}, "still_prepared_after_shutdown"),
        ):
            with self.subTest(expected=expected):
                clock = FakeClock()
                live_calls = []
                post_stop_calls = []
                stop_calls = []

                async def wait():
                    raise RECOVERY.RecoveryTimeoutError({"shard_0": 2, "shard_1": 2})

                async def count(
                    stop_calls=stop_calls,
                    post_stop_calls=post_stop_calls,
                    shutdown_counts=shutdown_counts,
                    live_calls=live_calls,
                ):
                    if stop_calls:
                        post_stop_calls.append(1)
                        return shutdown_counts
                    live_calls.append(1)
                    return {"shard_0": 1, "shard_1": 1}

                async def stop(stop_calls=stop_calls):
                    stop_calls.append(1)

                async def scenario(
                    clock=clock,
                    expected=expected,
                    shutdown_counts=shutdown_counts,
                    count=count,
                    stop=stop,
                ):
                    with self.assertRaises(RECOVERY.RecoveryTimeoutError) as raised:
                        await RECOVERY.wait_for_recovery_with_diagnostics(
                            wait,
                            count,
                            stop,
                            monotonic=clock.monotonic,
                            sleep=clock.sleep,
                            grace_seconds=0.3,
                            poll_interval=0.1,
                        )
                    self.assertEqual(raised.exception.diagnostic.status, expected)
                    self.assertEqual(
                        raised.exception.diagnostic.after_shutdown,
                        shutdown_counts,
                    )

                self.run_async(scenario())
                self.assertLessEqual(clock.now, 0.3)
                self.assertGreaterEqual(len(live_calls), 1)
                self.assertEqual(post_stop_calls, [1])
                self.assertEqual(stop_calls, [1])

    def test_diagnostic_read_error_does_not_replace_timeout_or_expose_details(self):
        clock = FakeClock()
        calls = 0
        stop_calls = []

        async def wait():
            raise RECOVERY.RecoveryTimeoutError({"shard_0": 1, "shard_1": 0})

        async def count():
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("sensitive database detail")
            return {"shard_0": 1, "shard_1": 0}

        async def stop():
            stop_calls.append(1)

        async def scenario():
            with self.assertRaises(RECOVERY.RecoveryTimeoutError) as raised:
                await RECOVERY.wait_for_recovery_with_diagnostics(
                    wait,
                    count,
                    stop,
                    monotonic=clock.monotonic,
                    sleep=clock.sleep,
                    grace_seconds=5.0,
                    poll_interval=0.1,
                )
            self.assertEqual(raised.exception.diagnostic.status, "live_observation_error")
            self.assertEqual(raised.exception.diagnostic.after_shutdown, {"shard_0": 1, "shard_1": 0})
            self.assertNotIn("sensitive database detail", str(raised.exception))

        self.run_async(scenario())
        self.assertEqual(calls, 2)
        self.assertEqual(stop_calls, [1])
        self.assertLessEqual(clock.now, 0.1)

    def test_slow_live_count_is_cancelled_at_query_bound_then_counted_once_after_stop(self):
        calls = 0
        stop_calls = []

        async def wait():
            raise RECOVERY.RecoveryTimeoutError({"shard_0": 1, "shard_1": 1})

        async def count():
            nonlocal calls
            calls += 1
            if not stop_calls:
                await asyncio.sleep(1.0)
            return {"shard_0": 1, "shard_1": 1}

        async def stop():
            stop_calls.append(1)

        async def scenario():
            start = time.monotonic()
            with self.assertRaises(RECOVERY.RecoveryTimeoutError) as raised:
                await RECOVERY.wait_for_recovery_with_diagnostics(
                    wait,
                    count,
                    stop,
                    grace_seconds=1.0,
                    poll_interval=0.1,
                    query_timeout=0.02,
                )
            self.assertLess(time.monotonic() - start, 0.2)
            self.assertEqual(raised.exception.diagnostic.status, "live_observation_timeout")
            self.assertEqual(raised.exception.diagnostic.after_shutdown, {"shard_0": 1, "shard_1": 1})

        self.run_async(scenario())
        self.assertEqual(calls, 2)
        self.assertEqual(stop_calls, [1])

    def test_successful_original_recovery_path_never_invokes_diagnostic_callbacks(self):
        calls = []

        async def wait():
            return None

        async def count():
            calls.append("count")
            return {"shard_0": 0, "shard_1": 0}

        async def stop():
            calls.append("stop")

        async def scenario():
            result = await RECOVERY.wait_for_recovery_with_diagnostics(wait, count, stop)
            self.assertIsNone(result)

        self.run_async(scenario())
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
