import tempfile
import unittest
from pathlib import Path

from agent_cli.skills import SkillValidationError, discover_skill_names, load_skills


EXPECTED_SKILLS = {
    "project-bootstrap",
    "repository-discovery",
    "brainstorming",
    "writing-spec",
    "architecture-design",
    "architecture-decision",
    "threat-modeling",
    "writing-plan",
    "test-driven-development",
    "systematic-debugging",
    "verification",
    "code-review",
    "cross-review",
    "review-adjudication",
    "security-review",
    "documentation-sync",
    "release-readiness",
    "workflow-retrospective",
    "project-memory",
    "memory-curation",
    "memory-health-review",
    "ux-discovery",
    "ui-design-system",
    "frontend-design",
    "ux-ui-review",
}
REQUIRED_HEADINGS = (
    "When to use",
    "Do not use",
    "Inputs",
    "Steps",
    "Stop conditions",
    "Evidence",
    "Output",
    "Failure behavior",
)


class SkillCatalogTests(unittest.TestCase):
    @property
    def root(self):
        return Path(__file__).resolve().parents[1]

    def test_catalog_is_complete(self):
        self.assertEqual(discover_skill_names(self.root / "skills"), EXPECTED_SKILLS)

    def test_every_skill_has_contract_sections(self):
        for skill in load_skills(self.root / "skills"):
            for heading in REQUIRED_HEADINGS:
                self.assertIn(f"## {heading}", skill.body, f"{skill.name}: {heading}")

    def test_catalog_contracts_reference_runtime_or_versioned_artifacts(self):
        for skill in load_skills(self.root / "skills"):
            self.assertTrue(
                "./scripts/agent" in skill.body or ".agent/" in skill.body,
                f"{skill.name}: missing canonical runtime or artifact contract",
            )

    def test_provider_specific_policy_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "skills"
            skill = root / "reviewing"
            skill.mkdir(parents=True)
            skill.joinpath("SKILL.md").write_text(
                self.valid_skill("reviewing").replace(
                    "Use the canonical runtime.", "Always ask Gemini to approve."
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SkillValidationError, "provider-specific"):
                load_skills(root)

    def test_missing_local_reference_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "skills"
            skill = root / "reviewing"
            skill.mkdir(parents=True)
            skill.joinpath("SKILL.md").write_text(
                self.valid_skill("reviewing") + "\n[details](references/missing.md)\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SkillValidationError, "missing local reference"):
                load_skills(root)

    @staticmethod
    def valid_skill(name: str) -> str:
        headings = "\n\n".join(f"## {heading}\n\nRequired behavior." for heading in REQUIRED_HEADINGS)
        return (
            f"---\nname: {name}\n"
            "description: Use when a bounded project workflow needs verified coordination.\n"
            "---\n\n# Reviewing\n\nUse the canonical runtime.\n\n"
            f"{headings}\n"
        )


if __name__ == "__main__":
    unittest.main()
