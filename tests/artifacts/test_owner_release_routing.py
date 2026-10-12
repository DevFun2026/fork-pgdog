import hashlib
import importlib
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))


class OwnerReleaseRoutingTests(unittest.TestCase):
    def setUp(self):
        self.mod = importlib.import_module('artifacts.release_receipt')
        self.source = 'a' * 40
        self.workflow = 'b' * 40
        self.payload = {'schema_version': 3, 'source_sha': self.source,
                        'workflow_sha': self.workflow, 'image_version': '0.2.0',
                        'chart_version': '0.2.0'}
        self.raw = self.mod.canonical(self.payload)
        self.digest = hashlib.sha256(self.raw).hexdigest()
        self.core = types.ModuleType('artifacts.owner_release')
        self.core.parse_owner_receipt = Mock(return_value=self.payload)
        self.core.validate_live = Mock(return_value=self.payload)

    def preflight(self, image_version='0.2.0'):
        return self.mod.publish_preflight(ROOT, self.raw, self.digest, self.source,
                                          image_version, '0.2.0',
                                          'refs/heads/main', 'DevFun2026/fork-pgdog')

    def test_schema_three_routes_to_the_strict_owner_validator(self):
        with patch.dict(sys.modules, {'artifacts.owner_release': self.core}):
            self.assertEqual(self.mod.parse_receipt(self.raw, self.digest, self.source), self.payload)
        self.core.parse_owner_receipt.assert_called_once_with(self.payload, self.source)

    def test_publication_requires_live_owner_validation_on_the_actual_dispatch(self):
        with patch.dict(sys.modules, {'artifacts.owner_release': self.core}), patch.dict(
                os.environ, {'GITHUB_ACTOR_ID': '107181711', 'GITHUB_SHA': self.workflow}):
            self.assertEqual(self.preflight(), self.payload)
        self.core.validate_live.assert_called_once_with(
            self.payload, actor_id='107181711', workflow_sha=self.workflow, root=ROOT)

    def test_changed_dispatch_versions_stop_before_live_validation(self):
        with patch.dict(sys.modules, {'artifacts.owner_release': self.core}), self.assertRaisesRegex(ValueError, 'versions'):
            self.preflight('0.2.1')
        self.core.validate_live.assert_not_called()

    def test_invalid_owner_receipt_does_not_fall_back_to_another_route(self):
        self.core.parse_owner_receipt.side_effect = ValueError('unapproved draft')
        with patch.dict(sys.modules, {'artifacts.owner_release': self.core}), self.assertRaisesRegex(ValueError, 'unapproved draft'):
            self.mod.parse_receipt(self.raw, self.digest, self.source)
        self.core.validate_live.assert_not_called()

    def test_integrity_failure_precedes_owner_validator(self):
        with patch.dict(sys.modules, {'artifacts.owner_release': self.core}), self.assertRaisesRegex(ValueError, 'SHA256'):
            self.mod.parse_receipt(self.raw, '0' * 64, self.source)
        self.core.parse_owner_receipt.assert_not_called()


if __name__ == '__main__':
    unittest.main()
