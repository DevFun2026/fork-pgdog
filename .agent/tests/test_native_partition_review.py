import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

from agent_cli.providers.base import Capability
from agent_cli.providers.gemini import GeminiAdapter
from agent_cli.review.models import ReviewPackageRequest
from agent_cli.review.partition_orchestrator import PartitionOrchestrator

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "native_partition_review", ROOT / "scripts/native_partition_review.py"
)
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)


class Adapter:
    provider = "gemini"
    default_model = "gemini-fixture"

    def __init__(self, raw):
        self.raw = raw

    def detect(self):
        return Capability("gemini", True, sys.executable, "fixture", True, True, None)

    def build_argv(self, request):
        # Synthetic process only. Source text is an inert argv value, never code.
        return (
            sys.executable,
            "-c",
            "print(" + repr(self.raw) + ")",
            "--print",
            "unused",
            "--json-schema",
            str(request.output_schema_path),
        )

    def parse(self, raw):
        return GeminiAdapter(command=("unused",), repository_root=ROOT).parse(raw)


class NativePartitionReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.com")
        (self.root / ".agent").mkdir()
        (self.root / ".agent/config.toml").write_bytes(
            (ROOT / ".agent/config.toml").read_bytes()
        )
        (self.root / "contract.md").write_text("Integration contract.\n")
        (self.root / "one.txt").write_text("before\n")
        self.git("add", ".")
        self.git("commit", "-m", "base")
        (self.root / "one.txt").write_text("before\nafter\n")
        self.git("add", ".")
        self.git("commit", "-m", "feature")
        self.request = ReviewPackageRequest(
            self.root,
            "HEAD~1",
            "HEAD",
            "codex",
            "gemini",
            (),
            "Review all contracts",
            {"tests": "passed"},
            500000,
            96000,
        )
        self.part = PartitionOrchestrator({}).prepare(
            self.request, integration_context_paths=("contract.md",)
        )
        self.child = self.part.children[0]
        raw = (self.child.path / "manifest.json").read_bytes()
        self.identity = {
            "source_path": str(self.child.path),
            "manifest_raw_sha256": sha256(raw).hexdigest(),
            "manifest_sha256": self.child.manifest_sha256,
            "root_manifest_sha256": self.part.manifest_sha256,
            "role": "child",
            "base_sha": self.child.manifest.base_sha,
            "head_sha": self.child.manifest.head_sha,
            "max_bytes": 500000,
            "max_tokens": 96000,
        }
        self.run_root = self.root / ".agent/.runs/terminal-evidence"
        self.run_root.mkdir(mode=0o700)

    def git(self, *args):
        return subprocess.run(
            ("git", *args), cwd=self.root, capture_output=True, check=True
        )

    def tearDown(self):
        self.temp.cleanup()

    def run_review(self, raw, executor=None):
        provider = native.NativeGeminiAdapter(
            Adapter(raw),
            self.root,
            self.run_root,
            {self.identity["manifest_raw_sha256"]: self.identity},
            executor=executor,
        )
        runtime = PartitionOrchestrator({"gemini": provider})
        return runtime.run_partition(
            self.part,
            self.request,
            approved_manifest_sha256=self.part.manifest_sha256,
            trusted_partition_enabled=True,
        )

    def test_supervised_empty_output_retains_bound_terminal_receipt(self):
        raw = json.dumps(
            {
                "status": "SUCCESS",
                "response": "",
                "denied_actions": [{"action": "command", "display_name": "RunCommand"}],
            }
        )
        result = self.run_review(raw)
        self.assertEqual(result.status, "review_pending")
        receipts = list(self.run_root.rglob("receipt.json"))
        self.assertEqual(
            len(receipts), 1, "confirmed invalid exit needs a separate terminal receipt"
        )
        receipt = json.loads(receipts[0].read_text())
        self.assertEqual(receipt["status"], "terminal_incomplete")
        self.assertEqual(receipt["exit_code"], 0)
        self.assertTrue(receipt["owned_process_group_ended"])
        self.assertEqual(receipt["root_manifest_sha256"], self.part.manifest_sha256)
        self.assertEqual(receipt["child_manifest_sha256"], self.child.manifest_sha256)
        for key in ("audit", "stdout", "stderr"):
            evidence = self.root / receipt["native_paths"][key]
            self.assertEqual(
                sha256(evidence.read_bytes()).hexdigest(), receipt[key + "_sha256"]
            )
        from agent_cli.review.partition_retry import validate_terminal_receipt

        validated, _, _ = validate_terminal_receipt(
            part=self.part,
            child=self.child,
            request=self.request,
            receipt_path=receipts[0],
        )
        self.assertEqual(
            validated["legacy_audit_sha256"],
            sha256((self.child.path / "audit.jsonl").read_bytes()).hexdigest(),
        )
        self.assertFalse((self.child.path / "findings.json").exists())
        state = json.loads(
            (self.part.root_package.path / "partition-results.json").read_text()
        )
        self.assertEqual(
            state["dispatches"]["child:" + self.child.path.name]["status"], "started"
        )

    def test_unsupervised_executor_cannot_mint_terminal_receipt(self):
        self.run_review("", executor=lambda *args: (0, "", ""))
        self.assertEqual(list(self.run_root.rglob("receipt.json")), [])

    def test_invalid_utf8_stdout_keeps_exact_bytes_for_terminal_retry(self):
        adapter = Adapter("")
        adapter.build_argv = lambda request: (
            sys.executable,
            "-c",
            "import os; os.write(1, bytes([255, 13, 10]))",
            "--print",
            "unused",
            "--json-schema",
            str(request.output_schema_path),
        )
        provider = native.NativeGeminiAdapter(
            adapter,
            self.root,
            self.run_root,
            {self.identity["manifest_raw_sha256"]: self.identity},
        )
        runtime = PartitionOrchestrator({"gemini": provider})
        result = runtime.run_partition(
            self.part,
            self.request,
            approved_manifest_sha256=self.part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        self.assertEqual(result.status, "review_pending")
        (receipt_path,) = self.run_root.rglob("receipt.json")
        receipt = json.loads(receipt_path.read_text())
        stdout_path = self.root / receipt["native_paths"]["stdout"]
        self.assertEqual(stdout_path.read_bytes(), bytes([255, 13, 10]))
        from agent_cli.review.partition_retry import validate_terminal_receipt

        validate_terminal_receipt(
            part=self.part,
            child=self.child,
            request=self.request,
            receipt_path=receipt_path,
        )

    def test_valid_pass_is_not_retry_eligible(self):
        body = {"verdict": "pass", "findings": []}
        result = self.run_review(
            json.dumps(
                {
                    "status": "SUCCESS",
                    "structured_output": body,
                    "response": json.dumps(body),
                }
            )
        )
        self.assertEqual(result.status, "integration_manifest_pending")
        self.assertEqual(list(self.run_root.rglob("receipt.json")), [])

    def test_supervised_receipt_drives_approved_retry_without_overwriting_original(
        self,
    ):
        output = self.root / "synthetic-provider-output.json"
        output.write_text(json.dumps({"status": "SUCCESS", "response": ""}))
        adapter = Adapter("")
        adapter.build_argv = lambda request: (
            sys.executable,
            "-c",
            "from pathlib import Path; import sys; print(Path(sys.argv[1]).read_text())",
            str(output),
            "--print",
            "unused",
            "--json-schema",
            str(request.output_schema_path),
        )
        provider = native.NativeGeminiAdapter(
            adapter,
            self.root,
            self.run_root,
            {self.identity["manifest_raw_sha256"]: self.identity},
        )
        runtime = PartitionOrchestrator({"gemini": provider})
        first = runtime.run_partition(
            self.part,
            self.request,
            approved_manifest_sha256=self.part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        self.assertEqual(first.status, "review_pending")
        original_audit = (self.child.path / "audit.jsonl").read_bytes()
        (receipt_path,) = self.run_root.rglob("receipt.json")
        retry = runtime.preview_retry(
            self.part,
            self.request,
            self.child.path,
            receipt_path,
            provider.retry_transport_identity(self.child),
        )
        body = {"verdict": "pass", "findings": []}
        output.write_text(
            json.dumps(
                {
                    "status": "SUCCESS",
                    "structured_output": body,
                    "response": json.dumps(body),
                }
            )
        )
        result = runtime.run_retry(
            self.part,
            self.request,
            retry,
            approved_retry_manifest_sha256=retry.manifest_sha256,
            trusted_partition_enabled=True,
        )
        self.assertEqual((result.status, result.verdict), ("completed", "pass"))
        self.assertEqual((self.child.path / "audit.jsonl").read_bytes(), original_audit)
        self.assertFalse((self.child.path / "findings.json").exists())
        resumed = runtime.run_partition(
            self.part,
            self.request,
            approved_manifest_sha256=self.part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        self.assertEqual(resumed.status, "integration_manifest_pending")
        state = runtime._state(self.part)
        self.assertEqual(
            state["dispatches"]["child:" + self.child.path.name]["status"], "started"
        )
        self.assertEqual(len(state["retry_attempts"]), 1)

    def test_valid_json_without_confirmed_group_end_stays_pending(self):
        from agent_cli.providers.native_supervisor import InvocationOutcome

        body = {"verdict": "pass", "findings": []}
        raw = json.dumps(
            {
                "status": "SUCCESS",
                "structured_output": body,
                "response": json.dumps(body),
            }
        )

        def unfinished_group(argv, cwd, stdout, stderr, timeout, **kwargs):
            stdout.write_text(raw)
            stderr.write_text("")
            return InvocationOutcome(
                0, 123, 123, "fixture:123", False, False, "start", "end"
            )

        with patch(
            "agent_cli.providers.native_supervisor.run_native",
            side_effect=unfinished_group,
        ):
            result = self.run_review(raw)
        self.assertEqual(result.status, "review_pending")
        self.assertFalse((self.child.path / "findings.json").exists())
        self.assertEqual(list(self.run_root.rglob("receipt.json")), [])

    def test_native_host_opt_in_precedes_root_access(self):
        with patch.object(
            native, "_git_root", side_effect=AssertionError("root accessed")
        ):
            with self.assertRaises(SystemExit) as raised:
                native.main(
                    [
                        "--root",
                        str(self.root),
                        "--package",
                        str(self.part.root_package.path),
                        "--approve-manifest",
                        self.part.manifest_sha256,
                    ]
                )
        self.assertEqual(raised.exception.code, 2)

    def test_transport_drift_after_binding_blocks_before_launch(self):
        adapter = Adapter(json.dumps({"status": "SUCCESS", "response": ""}))
        provider = native.NativeGeminiAdapter(
            adapter,
            self.root,
            self.run_root,
            {self.identity["manifest_raw_sha256"]: self.identity},
        )
        identity = provider.retry_transport_identity(self.child)
        provider.bind_retry_transport(self.child, identity)
        adapter.raw = "changed invocation argv"
        runtime = PartitionOrchestrator({"gemini": provider})
        from agent_cli.providers.native_supervisor import run_native

        with patch(
            "agent_cli.providers.native_supervisor.run_native", wraps=run_native
        ) as launch:
            with self.assertRaisesRegex(ValueError, "transport changed"):
                runtime.run_partition(
                    self.part,
                    self.request,
                    approved_manifest_sha256=self.part.manifest_sha256,
                    trusted_partition_enabled=True,
                )
        launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
