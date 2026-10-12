import contextlib
import io
import json
import runpy
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))


class OwnerReceiptCliTests(unittest.TestCase):
    def invoke(self, args):
        cli = runpy.run_path(str(ROOT / 'scripts/verify-artifacts'))
        output = io.StringIO()
        with patch.object(sys, 'argv', ['verify-artifacts', *args]), contextlib.redirect_stdout(output):
            result = cli['main']()
        return result, json.loads(output.getvalue())

    def test_explicit_draft_command_keeps_approval_pending(self):
        result = SimpleNamespace(path=Path('draft.json'), draft_sha256='a' * 64,
                                 approval_body='Approve this exact payload')
        args = ['owner-release-draft', '--output', '.agent/.runs/draft.json',
                '--source-sha', 'a' * 40, '--workflow-sha', 'b' * 40,
                '--source-pr', '9', '--workflow-pr', '10',
                '--source-review', '.agent/.runs/review-source',
                '--workflow-review', '.agent/.runs/review-workflow',
                '--source-assessment', '.agent/.runs/source-assessment.json',
                '--workflow-assessment', '.agent/.runs/workflow-assessment.json',
                '--image-version', '0.2.0', '--chart-version', '0.2.0',
                '--source-quality-run', '100', '--source-artifact-run', '101',
                '--workflow-quality-run', '102', '--workflow-artifact-run', '103']
        with patch('artifacts.owner_release_export.create_draft_receipt', return_value=result) as export:
            code, printed = self.invoke(args)
        self.assertEqual(code, 0)
        self.assertEqual(printed['status'], 'owner_approval_pending')
        self.assertEqual(printed['draft_sha256'], result.draft_sha256)
        self.assertEqual(export.call_args.kwargs['image_version'], '0.2.0')
        self.assertEqual(export.call_args.args[-1], {'source-quality': 100, 'source-artifacts': 101,
            'workflow-quality': 102, 'workflow-artifacts': 103})

    def test_finalization_passes_the_explicit_comment_id_to_live_validator(self):
        with patch('artifacts.owner_release_finalize.finalize_receipt', return_value='c' * 64) as finalize:
            code, printed = self.invoke(['owner-release-finalize', '--draft', '.agent/.runs/draft.json',
                '--output', '.agent/.runs/final.json', '--comment-id', '42'])
        self.assertEqual(code, 0)
        self.assertEqual(printed['receipt_sha256'], 'c' * 64)
        self.assertEqual(finalize.call_args.args[-1], 42)


if __name__ == '__main__':
    unittest.main()
