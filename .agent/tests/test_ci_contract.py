import re
import unittest
from pathlib import Path


EXPECTED_MERGE_COMMANDS = (
    "./scripts/agent doctor --ci",
    "./scripts/agent verify merge",
    "./scripts/agent docs check",
)


def contract_commands(path: Path) -> tuple[str, ...]:
    text = path.read_text(encoding="utf-8")
    block = text.split("agent-merge-contract:start", 1)[1].split(
        "agent-merge-contract:end", 1
    )[0]
    commands = []
    for line in block.splitlines():
        match = re.match(r"\s*-\s+(?:run:\s+)?(\./scripts/agent .+?)\s*$", line)
        if match:
            commands.append(match.group(1))
    return tuple(commands)


class CiContractTests(unittest.TestCase):
    @property
    def root(self):
        return Path(__file__).resolve().parents[2]

    def test_github_and_gitlab_call_same_merge_commands(self):
        self.assertEqual(
            contract_commands(self.root / ".github/workflows/agent-quality.yml"),
            EXPECTED_MERGE_COMMANDS,
        )
        self.assertEqual(
            contract_commands(self.root / ".gitlab-ci.yml"),
            EXPECTED_MERGE_COMMANDS,
        )

    def test_untrusted_github_job_has_no_provider_secrets(self):
        workflow = (self.root / ".github/workflows/agent-quality.yml").read_text(
            encoding="utf-8"
        )
        block = workflow.split("untrusted-job:start", 1)[1].split(
            "untrusted-job:end", 1
        )[0]
        for secret in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "CODEX_API_KEY"):
            self.assertNotIn(secret, block)

    def test_protected_jobs_materialize_remote_default_branch_anchor(self):
        github = (self.root / ".github/workflows/agent-quality.yml").read_text(
            encoding="utf-8"
        )
        gitlab = (self.root / ".gitlab-ci.yml").read_text(encoding="utf-8")
        protected_github = github.split("protected-merge-gate:", 1)[1]
        self.assertIn("fetch-depth: 0", protected_github)
        self.assertIn("GH_TOKEN: ${{ github.token }}", protected_github)
        self.assertIn("x-access-token:${GH_TOKEN}", protected_github)
        self.assertIn("refs/remotes/origin/$DEFAULT_BRANCH", github)
        self.assertIn('GIT_DEPTH: "0"', gitlab)
        self.assertIn("refs/remotes/origin/$CI_DEFAULT_BRANCH", gitlab)


if __name__ == "__main__":
    unittest.main()
