import hashlib
import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts.owner_release import approval_body
from artifacts.release_receipt import canonical
from test_owner_release import make_receipt


class FinalizeOwnerReceiptTests(unittest.TestCase):
    def fixture(self, root):
        run = root / '.agent/.runs'
        run.mkdir(parents=True)
        payload = make_receipt('d' * 40, 'e' * 40, 'a' * 40, 'b' * 40, 'c' * 40)
        payload['created_at'] = '2000-01-01T00:00:00Z'
        payload['authorization']['comment_id'] = 0
        payload['authorization']['comment_body_sha256'] = hashlib.sha256(approval_body(payload).encode()).hexdigest()
        draft = run / 'draft.json'
        draft.write_bytes(canonical(payload) + b'\n')
        return draft, run / 'final.json', payload

    def test_finalization_checks_actual_owner_before_writing_new_receipt(self):
        mod = importlib.import_module('artifacts.owner_release_finalize')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            draft, output, payload = self.fixture(root)
            original = draft.read_bytes()
            api = Mock(return_value={'id': 107181711})
            with patch.object(mod, 'validate_live') as live:
                digest = mod.finalize_receipt(root, draft, output, 42, api=api)
            result = json.loads(output.read_bytes())
            self.assertEqual(result['authorization']['comment_id'], 42)
            self.assertEqual(approval_body(result), approval_body(payload))
            self.assertEqual(digest, hashlib.sha256(canonical(result)).hexdigest())
            live.assert_called_once_with(result, actor_id='107181711',
                workflow_sha=payload['workflow_sha'], root=root.resolve(), api=api)
            api.assert_called_once_with('user')
            self.assertEqual(draft.read_bytes(), original)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_revoked_owner_approval_leaves_no_final_receipt(self):
        mod = importlib.import_module('artifacts.owner_release_finalize')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            draft, output, _ = self.fixture(root)
            with patch.object(mod, 'validate_live', side_effect=ValueError('withdrawn')), self.assertRaisesRegex(ValueError, 'withdrawn'):
                mod.finalize_receipt(root, draft, output, 42, api=Mock(return_value={'id': 107181711}))
            self.assertFalse(output.exists())

    def test_existing_output_and_symlink_inputs_are_preserved(self):
        mod = importlib.import_module('artifacts.owner_release_finalize')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            draft, output, _ = self.fixture(root)
            output.write_text('preserved')
            with self.assertRaises(ValueError):
                mod.finalize_receipt(root, draft, output, 42, api=Mock())
            self.assertEqual(output.read_text(), 'preserved')
            alias = draft.parent / 'alias.json'
            alias.symlink_to(draft)
            with self.assertRaises(ValueError):
                mod.finalize_receipt(root, alias, draft.parent / 'new.json', 42, api=Mock())

    def test_draft_and_output_must_remain_inside_local_run_directory(self):
        mod = importlib.import_module('artifacts.owner_release_finalize')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            draft, _, _ = self.fixture(root)
            with self.assertRaises(ValueError):
                mod.finalize_receipt(root, draft, root / 'outside.json', 42, api=Mock())


if __name__ == '__main__':
    unittest.main()
