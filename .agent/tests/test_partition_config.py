import unittest
from pathlib import Path

from agent_cli.config import load_config


class PartitionConfigTests(unittest.TestCase):
    def test_review_has_explicit_partition_limits(self):
        config = load_config(Path(".agent/config.toml"))
        self.assertTrue(config.review.partition_enabled)
        self.assertEqual(config.review.max_aggregate_bytes, 2500000)
        self.assertEqual(config.review.max_aggregate_tokens, 800000)
        self.assertEqual(config.review.partition_target_bytes, 250000)
