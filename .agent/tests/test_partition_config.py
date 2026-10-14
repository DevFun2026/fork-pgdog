import unittest
from pathlib import Path

from agent_cli.config import load_config


class PartitionConfigTests(unittest.TestCase):
    def test_review_has_explicit_partition_limits(self):
        config = load_config(Path(".agent/config.toml"))
        self.assertTrue(config.review.partition_enabled)
        self.assertEqual(config.review.max_package_bytes, 500000)
        self.assertEqual(config.review.max_estimated_tokens, 96000)
        self.assertEqual(config.review.max_aggregate_bytes, 30000000)
        self.assertEqual(config.review.max_aggregate_tokens, 8000000)
        self.assertEqual(config.review.partition_target_bytes, 250000)

    def test_unconfigured_projects_keep_conservative_runtime_defaults(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.toml'
            path.write_text('[project]\nname = "fixture"\n')
            config = load_config(path)
        self.assertFalse(config.review.partition_enabled)
        self.assertEqual(config.review.max_package_bytes, 500000)
        self.assertEqual(config.review.max_estimated_tokens, 64000)
        self.assertEqual(config.review.partition_target_bytes, 250000)
        self.assertEqual(config.review.max_aggregate_bytes, 2500000)
        self.assertEqual(config.review.max_aggregate_tokens, 800000)
