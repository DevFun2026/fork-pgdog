import contextlib
import io
import unittest
from unittest.mock import patch

from agent_cli.cli import build_parser, main
from agent_cli.verify import GateResult


class VerifyTimeoutTests(unittest.TestCase):
    def test_default_preserves_sixty_second_limit(self):
        self.assertEqual(build_parser().parse_args(['verify', 'merge']).timeout, 60)

    def test_zero_and_negative_timeout_are_rejected(self):
        for value in ('0', '-1'):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    build_parser().parse_args(['verify', 'merge', '--timeout', value])
                self.assertEqual(error.exception.code, 2)

    def test_custom_timeout_reaches_gate(self):
        with patch('agent_cli.cli.run_gate', return_value=GateResult('review', 'passed', (), ())) as gate:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['verify', 'review', '--timeout', '3600', '--json']), 0)
            self.assertEqual(gate.call_args.kwargs['timeout'], 3600)
