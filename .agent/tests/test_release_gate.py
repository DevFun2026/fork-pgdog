import unittest

from agent_cli.security import ReleaseContext, release_check


class ReleaseGateTests(unittest.TestCase):
    def context(self, **changes):
        values = dict(
            merge_status="passed",
            security_status="passed",
            threat_model_delta_required=False,
            threat_model_delta_present=False,
            scanner_statuses={
                "dependency": "passed",
                "license": "passed",
                "sast": "passed",
                "iac": "not-configured",
                "container": "not-configured",
            },
            required_scanners=("dependency", "license", "sast"),
            clean_checkout_smoke=True,
            documentation_current=True,
            release_notes=True,
            migration_backup_rollback=True,
            residual_risks=True,
        )
        values.update(changes)
        return ReleaseContext(**values)

    def test_required_scanner_skip_blocks_release(self):
        context = self.context(
            scanner_statuses={
                "dependency": "passed",
                "license": "skipped",
                "sast": "passed",
            }
        )
        result = release_check(context)
        self.assertEqual(result.status, "blocked")
        self.assertIn("required scanner license: skipped", result.reasons)

    def test_missing_required_scanner_blocks_release(self):
        context = self.context(
            scanner_statuses={
                "dependency": "passed",
                "license": "passed",
            }
        )
        result = release_check(context)
        self.assertEqual(result.status, "blocked")
        self.assertIn("required scanner sast: not-configured", result.reasons)

    def test_unconfigured_optional_scanner_is_recorded_but_does_not_block(self):
        result = release_check(self.context())
        self.assertEqual(result.status, "passed")
        self.assertIn("iac", result.not_configured)
        self.assertIn("container", result.not_configured)

    def test_required_threat_model_delta_blocks_when_missing(self):
        result = release_check(
            self.context(
                threat_model_delta_required=True,
                threat_model_delta_present=False,
            )
        )
        self.assertEqual(result.status, "blocked")
        self.assertIn("threat-model-delta", result.reasons)


if __name__ == "__main__":
    unittest.main()
