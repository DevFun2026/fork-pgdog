import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path

from agent_cli.verify import read_workflow_state
from agent_cli.workflow import (
    TransitionError,
    WorkflowState,
    transition,
)


class WorkflowTests(unittest.TestCase):
    def test_interface_guide_is_optional_and_keeps_gates(self):
        from agent_cli.cli import main
        from agent_cli.workflow import workflow_guide
        ux_skills = {"ux-discovery", "ui-design-system", "frontend-design", "ux-ui-review"}
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["workflow", "guide", "--task", "interface"]), 0)
        guide = json.loads(output.getvalue())
        self.assertEqual(guide["context_profile"], "standard")
        self.assertTrue(guide["merge_release_gates_unchanged"])
        self.assertTrue(ux_skills.issubset(guide["skills_on_demand"]))
        for task in ("content", "behavior", "architecture", "security"):
            self.assertTrue(ux_skills.isdisjoint(workflow_guide(task)["skills_on_demand"]))

    def test_guides_scale_ceremony_without_relaxing_gates(self):
        from agent_cli.cli import main
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for task, profile in (("content", "light"), ("behavior", "standard"),
                                  ("architecture", "deep"), ("security", "deep")):
                output = StringIO()
                with mock.patch("agent_cli.cli.ROOT", root), redirect_stdout(output):
                    self.assertEqual(main(["workflow", "guide", "--task", task]), 0)
                result = json.loads(output.getvalue())
                self.assertEqual(result["context_profile"], profile)
                self.assertTrue(result["merge_release_gates_unchanged"])
            self.assertFalse((root / ".agent").exists())

    def test_missing_state_file_defaults_to_discovered(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                read_workflow_state(Path(directory)), WorkflowState.DISCOVERED
            )

    def test_cannot_skip_from_designed_to_release_ready(self):
        with self.assertRaises(TransitionError):
            transition(WorkflowState.DESIGNED, WorkflowState.RELEASE_READY)

    def test_can_advance_one_state(self):
        self.assertEqual(
            transition(WorkflowState.DESIGNED, WorkflowState.PLAN_APPROVED),
            WorkflowState.PLAN_APPROVED,
        )

    def test_can_return_to_earlier_state(self):
        self.assertEqual(
            transition(WorkflowState.CROSS_REVIEWED, WorkflowState.DESIGNED),
            WorkflowState.DESIGNED,
        )


if __name__ == "__main__":
    unittest.main()
