from dataclasses import dataclass, replace
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from agent_cli.providers.base import Capability, ProviderResult
from agent_cli.review.models import ReviewPackageRequest
from agent_cli.review.orchestrator import ReviewOrchestrator
from agent_cli.review.package import load_package, ReviewPackageBlocked


@dataclass
class StubProvider:
    result: ProviderResult
    provider: str = "claude"
    calls: int = 0
    detect_calls: int = 0

    def detect(self):
        self.detect_calls += 1
        return Capability(self.provider, True, self.provider, "1", True, True, None)

    def review(self, request):
        self.calls += 1
        return self.result


@dataclass
class IsolationCheckingProvider(StubProvider):
    repository_root: Path | None = None

    def review(self, request):
        assert self.repository_root is not None
        self.calls += 1
        with self.assert_outside_repository(request.package_path):
            pass
        self.assert_package_inventory(request.package_path)
        return self.result

    def assert_outside_repository(self, package_path: Path):
        class OutsideAssertion:
            def __enter__(inner_self):
                with __import__("unittest").TestCase().assertRaises(ValueError):
                    package_path.resolve().relative_to(self.repository_root.resolve())

            def __exit__(inner_self, exc_type, exc, traceback):
                return False

        return OutsideAssertion()

    @staticmethod
    def assert_package_inventory(package_path: Path):
        names = {
            path.relative_to(package_path).as_posix()
            for path in package_path.rglob("*")
            if path.is_file()
        }
        assert names == {
            "context/file.txt",
            "diff.patch",
            "manifest.json",
            "instructions.md",
            "policy.md",
            "requirements.md",
            "review-schema.json",
            "verification.json",
        }


class OrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        subprocess.run(("git", "init", "-b", "main"), cwd=self.root, check=True, capture_output=True)
        subprocess.run(("git", "config", "user.email", "fixture@example.com"), cwd=self.root, check=True)
        subprocess.run(("git", "config", "user.name", "Fixture"), cwd=self.root, check=True)
        (self.root / "file.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(("git", "add", "file.txt"), cwd=self.root, check=True)
        subprocess.run(("git", "commit", "-m", "one"), cwd=self.root, check=True, capture_output=True)
        (self.root / "file.txt").write_text("one\ntwo\n", encoding="utf-8")
        subprocess.run(("git", "add", "file.txt"), cwd=self.root, check=True)
        subprocess.run(("git", "commit", "-m", "two"), cwd=self.root, check=True, capture_output=True)
        self.request = ReviewPackageRequest(
            root=self.root,
            base="HEAD~1",
            head="HEAD",
            author_provider="gemini",
            reviewer_provider="claude",
            context_paths=("file.txt",),
            requirements="Review the change.",
            verification={"tests": "passed"},
            max_package_bytes=500000,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_resume_rechecks_budget_before_provider_probe(self):
        provider = StubProvider(ProviderResult.timeout("claude"))
        orchestrator = ReviewOrchestrator({"claude": provider})
        package = orchestrator.prepare(self.request)
        with self.assertRaisesRegex(ReviewPackageBlocked, "context budget"):
            orchestrator.run_package(package, replace(self.request, max_estimated_tokens=1),
                                     approved_manifest_sha256=package.manifest_sha256)
        self.assertEqual(provider.detect_calls, 0)
        self.assertEqual(provider.calls, 0)


    def test_timeout_is_review_pending_and_preserves_package(self):
        provider = StubProvider(
            ProviderResult.timeout("claude", "auth sk-aaaaaaaaaaaaaaaaaaaaaaaa")
        )
        orchestrator = ReviewOrchestrator({"claude": provider})
        package = orchestrator.prepare(self.request)
        result = orchestrator.run(
            self.request, approved_manifest_sha256=package.manifest_sha256
        )
        self.assertEqual(result.status, "review_pending")
        self.assertTrue(result.package_path.exists())
        self.assertEqual(provider.calls, 1)
        audit = json.loads((result.package_path / "audit.jsonl").read_text())
        self.assertEqual(audit["error"], "auth [REDACTED_SECRET]")

    def test_malformed_json_never_becomes_approval(self):
        provider = StubProvider(ProviderResult.invalid("claude", "not json"))
        orchestrator = ReviewOrchestrator({"claude": provider})
        package = orchestrator.prepare(self.request)
        result = orchestrator.run(
            self.request, approved_manifest_sha256=package.manifest_sha256
        )
        self.assertIsNone(result.verdict)
        self.assertEqual(result.status, "review_pending")

    def test_missing_manifest_approval_never_calls_provider(self):
        provider = StubProvider(ProviderResult.timeout("claude"))
        result = ReviewOrchestrator({"claude": provider}).run(self.request)
        self.assertEqual(result.status, "manifest_pending")
        self.assertEqual(provider.calls, 0)
        self.assertEqual(provider.detect_calls, 0)

    def test_package_can_resume_in_new_orchestrator_after_manifest_approval(self):
        provider = StubProvider(
            ProviderResult(
                provider="claude",
                status="completed",
                verdict="pass",
                findings_json='{"verdict":"pass","findings":[]}',
                exit_code=0,
                stdout_sha256="a" * 64,
                stderr_excerpt="",
            )
        )
        first = ReviewOrchestrator({"claude": provider})
        prepared = first.prepare(self.request)
        resumed = load_package(prepared.path, root=self.root)
        result = ReviewOrchestrator({"claude": provider}).run_package(
            resumed,
            self.request,
            approved_manifest_sha256=prepared.manifest_sha256,
        )
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.verdict, "pass")
        self.assertEqual(provider.calls, 1)

    def test_provider_runs_from_isolated_package_outside_repository(self):
        provider = IsolationCheckingProvider(
            ProviderResult(
                provider="claude",
                status="completed",
                verdict="pass",
                findings_json='{"verdict":"pass","findings":[]}',
                exit_code=0,
                stdout_sha256="b" * 64,
                stderr_excerpt="",
            ),
            repository_root=self.root,
        )
        package = ReviewOrchestrator({"claude": provider}).prepare(self.request)

        result = ReviewOrchestrator({"claude": provider}).run_package(
            package,
            self.request,
            approved_manifest_sha256=package.manifest_sha256,
        )

        self.assertEqual(result.status, "completed")
        self.assertEqual(provider.calls, 1)


if __name__ == "__main__":
    unittest.main()
