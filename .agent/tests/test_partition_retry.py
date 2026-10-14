import hashlib
import json
import shutil
import unittest
import uuid
from dataclasses import replace

from agent_cli.review.partition_orchestrator import PartitionOrchestrator, _retry_usage
from agent_cli.review.partition_retry import input_inventory


class PartitionRetryTests(unittest.TestCase):
    def setUp(self):
        from test_partition_orchestrator import PartitionOrchestratorTests

        self.fixture = PartitionOrchestratorTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.runtime = self.fixture.runtime
        self.provider = self.fixture.provider
        self.request = self.fixture.request
        self.root = self.fixture.root
        self.part = self.fixture.prepare()
        self.child = self.part.children[0]

    @staticmethod
    def sha(data):
        return hashlib.sha256(data).hexdigest()

    def terminal_receipt(self, *, status="terminal_incomplete", exit_code=0, source_package=None):
        source = source_package or self.child
        canonical_audit = {
            "status": "incomplete",
            "manifest_sha256": source.manifest_sha256,
            "provider": source.manifest.reviewer_provider,
            "exit_code": 0,
            "stdout_sha256": self.sha(b"old stdout"),
            "verdict": None,
        }
        audit_raw = json.dumps(canonical_audit, sort_keys=True).encode() + b"\n"
        if (source.path / "audit.jsonl").exists():
            audit_raw = (source.path / "audit.jsonl").read_bytes()
        else:
            (source.path / "audit.jsonl").write_bytes(audit_raw)
        if self.runtime._marker(
            self.part, f"child:{self.child.path.name}", self.child
        ) is None:
            self.runtime._set_marker(
                self.part,
                self.runtime._state(self.part),
                f"child:{self.child.path.name}",
                self.child,
                "started",
            )
        files, inventory_sha = input_inventory(self.child)
        evidence = (
            self.root / ".agent/.runs/terminal-evidence"
            / source.path.name / f"invocation-{uuid.uuid4()}"
        )
        evidence.mkdir(parents=True)
        stdout = b"old stdout"
        stderr = b"old stderr"
        native_audit = {
            "status": "review_pending",
            "payload_unchanged": True,
            "manifest_identity_unchanged": True,
            "root_manifest_sha256": self.part.manifest_sha256,
            "package_manifest_sha256": source.manifest_sha256,
            "stdout_sha256": self.sha(stdout),
            "prompt_sha256": self.sha(b"old prompt"),
            "exit_code": 0,
            "invocation_id": evidence.name,
            "pid": 123,
            "pgid": 123,
            "process_start_identity": f"{'a' * 32}:123",
            "owned_process_group_ended": True,
            "timed_out": False,
        }
        native_audit_raw = json.dumps(native_audit, sort_keys=True).encode() + b"\n"
        (evidence / "audit.jsonl").write_bytes(native_audit_raw)
        (evidence / "stdout.txt").write_bytes(stdout)
        (evidence / "stderr.txt").write_bytes(stderr)
        receipt = {
            "version": 1,
            "root_manifest_sha256": self.part.manifest_sha256,
            "child_manifest_sha256": source.manifest_sha256,
            "invocation_id": evidence.name,
            "pid": 123,
            "pgid": 123,
            "process_start_identity": f"{'a' * 32}:123",
            "exit_code": exit_code,
            "owned_process_group_ended": True,
            "status": status,
            "prompt_sha256": self.sha(b"old prompt"),
            "input_inventory_sha256": inventory_sha,
            "stdout_sha256": self.sha(stdout),
            "stderr_sha256": self.sha(stderr),
            "audit_sha256": self.sha(native_audit_raw),
            "native_paths": {
                name: (evidence / filename).relative_to(self.root).as_posix()
                for name, filename in (
                    ("audit", "audit.jsonl"),
                    ("stdout", "stdout.txt"),
                    ("stderr", "stderr.txt"),
                )
            },
            "legacy_audit_sha256": self.sha(audit_raw),
        }
        receipt_path = evidence / "receipt.json"
        receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        return receipt_path

    def preview(self, *, status="terminal_incomplete", exit_code=0, max_attempts=2):
        receipt = self.terminal_receipt(status=status, exit_code=exit_code)
        transport = {
            "model": "fixture-model",
            "executable_sha256": self.sha(b"executable"),
            "prompt_sha256": self.sha(b"new prompt"),
            "argv_sha256": self.sha(b"normalized argv"),
        }
        retry = self.runtime.preview_retry(
            self.part,
            self.request,
            self.child.path,
            receipt,
            transport,
            max_attempts,
        )
        return retry, receipt

    def rewrite_supervised_identity(self, receipt_path, *, pid, pgid, identity):
        receipt = json.loads(receipt_path.read_text())
        audit_path = self.root / receipt["native_paths"]["audit"]
        native_audit = json.loads(audit_path.read_text())
        for record in (receipt, native_audit):
            record["pid"] = pid
            record["pgid"] = pgid
            record["process_start_identity"] = identity
        audit_raw = json.dumps(native_audit, sort_keys=True).encode() + b"\n"
        audit_path.write_bytes(audit_raw)
        receipt["audit_sha256"] = self.sha(audit_raw)
        receipt_path.write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":"))
        )

    def test_retry_preview_and_runner_are_explicit_orchestrator_operations(self):
        self.assertTrue(callable(getattr(PartitionOrchestrator, "preview_retry", None)))
        self.assertTrue(callable(getattr(PartitionOrchestrator, "run_retry", None)))

    def test_legacy_integration_context_shape_is_preserved_without_retries(self):
        self.runtime.run_partition(
            self.part,
            self.request,
            approved_manifest_sha256=self.part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        context = json.loads(
            self.runtime._integration_context(self.part)["partition-review-results.json"]
        )
        self.assertEqual(
            set(context),
            {
                "root_manifest_sha256", "base_sha", "head_sha",
                "full_diff_sha256", "scope", "children", "shards",
                "required_review",
            },
        )

    def test_transport_identity_drift_blocks_before_probe(self):
        retry, _receipt = self.preview()
        self.provider.identity_drift = True
        probes, calls = self.provider.probes, self.provider.calls
        with self.assertRaisesRegex(ValueError, "transport identity changed"):
            self.runtime.run_retry(
                self.part,
                self.request,
                retry,
                approved_retry_manifest_sha256=retry.manifest_sha256,
                trusted_partition_enabled=True,
            )
        self.assertEqual((self.provider.probes, self.provider.calls), (probes, calls))

    def test_unapproved_retry_does_not_probe_or_change_original_artifacts(self):
        retry, _receipt = self.preview()
        audit_before = (self.child.path / "audit.jsonl").read_bytes()
        probes, calls = self.provider.probes, self.provider.calls
        result = self.runtime.run_retry(
            self.part,
            self.request,
            retry,
            trusted_partition_enabled=True,
        )
        self.assertEqual(result.status, "manifest_pending")
        self.assertEqual((self.provider.probes, self.provider.calls), (probes, calls))
        self.assertEqual((self.child.path / "audit.jsonl").read_bytes(), audit_before)

    def test_approved_retry_uses_clone_and_is_selected_for_integration(self):
        retry, _receipt = self.preview()
        retry = self.runtime.load_retry(self.part, self.request, retry.manifest_path)
        original_audit = (self.child.path / "audit.jsonl").read_bytes()
        original_marker = (self.part.root_package.path / "partition-results.json").read_bytes()
        result = self.runtime.run_retry(
            self.part,
            self.request,
            retry,
            approved_retry_manifest_sha256=retry.manifest_sha256,
            trusted_partition_enabled=True,
        )
        self.assertEqual((result.status, result.verdict), ("completed", "pass"))
        calls = self.provider.calls
        with self.assertRaisesRegex(ValueError, "replayed or over limit"):
            self.runtime.run_retry(
                self.part,
                self.request,
                retry,
                approved_retry_manifest_sha256=retry.manifest_sha256,
                trusted_partition_enabled=True,
            )
        self.assertEqual(self.provider.calls, calls)
        self.assertEqual((self.child.path / "audit.jsonl").read_bytes(), original_audit)
        self.assertNotEqual(
            (self.part.root_package.path / "partition-results.json").read_bytes(),
            original_marker,
        )
        self.assertEqual(
            json.loads((retry.package.path / "manifest.json").read_text())["head_sha"],
            self.part.root_package.manifest.head_sha,
        )
        pending = self.runtime.run_partition(
            self.part,
            self.request,
            approved_manifest_sha256=self.part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        self.assertEqual(pending.status, "integration_manifest_pending")
        self.assertFalse(self.runtime.clearance_valid(self.part))

    def test_receipt_evidence_hash_drift_blocks_before_probe(self):
        retry, receipt = self.preview()
        data = json.loads(receipt.read_text())
        stdout_path = self.root / data["native_paths"]["stdout"]
        stdout_path.write_bytes(b"tampered")
        probes, calls = self.provider.probes, self.provider.calls
        with self.assertRaises(ValueError):
            self.runtime.run_retry(
                self.part,
                self.request,
                retry,
                approved_retry_manifest_sha256=retry.manifest_sha256,
                trusted_partition_enabled=True,
            )
        self.assertEqual((self.provider.probes, self.provider.calls), (probes, calls))

    def test_original_audit_drift_after_retry_blocks_integration(self):
        retry, _receipt = self.preview()
        self.runtime.run_retry(
            self.part,
            self.request,
            retry,
            approved_retry_manifest_sha256=retry.manifest_sha256,
            trusted_partition_enabled=True,
        )
        (self.child.path / "audit.jsonl").write_text('{"status":"incomplete"}\n')
        with self.assertRaisesRegex(ValueError, "original child audit changed"):
            self.runtime.integration_package(self.part, self.request)

    def test_retry_manifest_drift_after_pass_blocks_integration(self):
        retry, _receipt = self.preview()
        self.runtime.run_retry(
            self.part,
            self.request,
            retry,
            approved_retry_manifest_sha256=retry.manifest_sha256,
            trusted_partition_enabled=True,
        )
        retry.manifest_path.write_text("{}\n")
        with self.assertRaises(ValueError):
            self.runtime.integration_package(self.part, self.request)

    def test_terminal_receipt_drift_after_pass_blocks_integration(self):
        retry, receipt = self.preview()
        self.runtime.run_retry(
            self.part,
            self.request,
            retry,
            approved_retry_manifest_sha256=retry.manifest_sha256,
            trusted_partition_enabled=True,
        )
        receipt.write_text("{}\n")
        with self.assertRaises(ValueError):
            self.runtime.integration_package(self.part, self.request)

    def test_original_child_input_tampering_blocks_retry(self):
        retry, _receipt = self.preview()
        source = next((self.child.path / "context").iterdir())
        original = source.read_bytes()
        source.write_bytes(original + b"tampered")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.runtime.run_retry(
                self.part,
                self.request,
                retry,
                approved_retry_manifest_sha256=retry.manifest_sha256,
                trusted_partition_enabled=True,
            )
        self.assertEqual(self.provider.probes, 0)

    def test_original_audit_tampering_blocks_retry(self):
        retry, _receipt = self.preview()
        audit = self.child.path / "audit.jsonl"
        audit.write_bytes(audit.read_bytes() + b"tampered")
        with self.assertRaisesRegex(ValueError, "audit changed"):
            self.runtime.run_retry(
                self.part,
                self.request,
                retry,
                approved_retry_manifest_sha256=retry.manifest_sha256,
                trusted_partition_enabled=True,
            )
        self.assertEqual(self.provider.probes, 0)

    def test_running_or_nonzero_receipt_is_rejected_during_preview(self):
        with self.assertRaises(ValueError):
            self.preview(status="running")
        with self.assertRaises(ValueError):
            self.preview(exit_code=1)

    def test_terminal_receipt_requires_supervisor_process_identity_shape(self):
        invalid_identities = (
            (123, 124, f"{'a' * 32}:123"),
            (123, 123, f"{'a' * 32}:999"),
        )
        for pid, pgid, identity in invalid_identities:
            with self.subTest(pid=pid, pgid=pgid, identity=identity):
                receipt = self.terminal_receipt()
                self.rewrite_supervised_identity(
                    receipt, pid=pid, pgid=pgid, identity=identity
                )
                with self.assertRaises(ValueError):
                    self.runtime.preview_retry(
                        self.part,
                        self.request,
                        self.child.path,
                        receipt,
                        {
                            "model": "fixture-model",
                            "executable_sha256": self.sha(b"executable"),
                            "prompt_sha256": self.sha(b"new prompt"),
                            "argv_sha256": self.sha(b"normalized argv"),
                        },
                    )

    def test_valid_old_pass_cannot_be_retried_or_changed(self):
        self.runtime.run_partition(
            self.part,
            self.request,
            approved_manifest_sha256=self.part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        audit = (self.child.path / "audit.jsonl").read_bytes()
        findings = (self.child.path / "findings.json").read_bytes()
        with self.assertRaises(ValueError):
            self.preview()
        self.assertEqual((self.child.path / "audit.jsonl").read_bytes(), audit)
        self.assertEqual((self.child.path / "findings.json").read_bytes(), findings)

    def test_root_lock_prevents_a_concurrent_retry_dispatch(self):
        retry, _receipt = self.preview()
        lock = self.runtime._claim_operation(self.part)
        try:
            probes, calls = self.provider.probes, self.provider.calls
            result = self.runtime.run_retry(
                self.part,
                self.request,
                retry,
                approved_retry_manifest_sha256=retry.manifest_sha256,
                trusted_partition_enabled=True,
            )
            self.assertEqual(result.status, "review_pending")
            self.assertEqual((self.provider.probes, self.provider.calls), (probes, calls))
        finally:
            self.runtime._release_operation(lock)

    def test_terminal_fail_is_recorded_and_never_creates_clearance(self):
        retry, _receipt = self.preview()
        self.provider.fail_at = 1
        result = self.runtime.run_retry(
            self.part,
            self.request,
            retry,
            approved_retry_manifest_sha256=retry.manifest_sha256,
            trusted_partition_enabled=True,
        )
        self.assertEqual((result.status, result.verdict), ("completed", "fail"))
        state = json.loads((self.part.root_package.path / "partition-results.json").read_text())
        self.assertEqual(state["retry_attempts"][0]["status"], "completed")
        resumed = self.runtime.run_partition(
            self.part,
            self.request,
            approved_manifest_sha256=self.part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        self.assertEqual((resumed.status, resumed.verdict), ("completed", "fail"))
        self.assertFalse(self.runtime.clearance_valid(self.part))

    def test_attempt_limit_is_monotonic(self):
        retry, _receipt = self.preview(max_attempts=1)
        self.provider.fail_at = 1
        self.runtime.run_retry(
            self.part,
            self.request,
            retry,
            approved_retry_manifest_sha256=retry.manifest_sha256,
            trusted_partition_enabled=True,
        )
        with self.assertRaises(ValueError):
            self.runtime.preview_retry(
                self.part,
                self.request,
                self.child.path,
                retry.receipt_path,
                dict(retry.transport_identity),
                max_attempts=1,
            )

    def test_valid_terminal_result_cannot_be_retried(self):
        retry, receipt = self.preview(max_attempts=2)
        self.provider.fail_at = 1
        self.runtime.run_retry(
            self.part,
            self.request,
            retry,
            approved_retry_manifest_sha256=retry.manifest_sha256,
            trusted_partition_enabled=True,
        )
        with self.assertRaisesRegex(ValueError, "terminal retry result"):
            self.runtime.preview_retry(
                self.part,
                self.request,
                self.child.path,
                receipt,
                dict(retry.transport_identity),
                max_attempts=2,
            )

    def test_loaded_manifest_cannot_raise_the_retry_limit(self):
        retry, _receipt = self.preview()
        manifest = dict(retry.manifest)
        manifest["max_attempts"] = 3
        retry.manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
        with self.assertRaisesRegex(ValueError, "attempt limit is invalid"):
            self.runtime.load_retry(self.part, self.request, retry.manifest_path)

    def test_retry_aggregate_budget_counts_attempts_for_every_child(self):
        other_path = self.root / ".agent/.runs/review-other-child"
        shutil.copytree(self.child.path, other_path)
        other_child = replace(self.child, path=other_path)
        part = replace(self.part, children=(self.child, other_child))
        max_bytes = part.manifest["limits"]["max_aggregate_bytes"]
        rows = []
        for index, child in enumerate((self.child, other_child), start=1):
            rows.append({
                "child_path": child.path.name,
                "attempt": 1,
                "retry_manifest_sha256": self.sha(f"retry-{index}".encode()),
                "receipt_sha256": self.sha(f"receipt-{index}".encode()),
                "package_path": f"retry-package-{index}",
                "source_package_path": child.path.name,
                "package_bytes": max_bytes,
                "estimated_tokens": 1,
                "status": "completed",
                "result": {},
            })
        state = {
            "root_manifest_sha256": part.manifest_sha256,
            "children": [],
            "integration": None,
            "dispatches": {},
            "retry_attempts": rows,
        }
        (part.root_package.path / "partition-results.json").write_text(
            json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n"
        )
        self.assertEqual(_retry_usage(self.runtime._state(part)), (2 * max_bytes, 2))
        with self.assertRaisesRegex(ValueError, "aggregate review budget"):
            self.runtime._integration_budget(part, self.request, 1)

    def test_second_attempt_requires_a_fresh_receipt_for_first_retry_clone(self):
        first, _old_receipt = self.preview(max_attempts=2)
        self.provider.invalid_at = 1
        first_result = self.runtime.run_retry(
            self.part,
            self.request,
            first,
            approved_retry_manifest_sha256=first.manifest_sha256,
            trusted_partition_enabled=True,
        )
        self.assertEqual(first_result.status, "review_pending")
        source_audit = {
            "status": "incomplete",
            "manifest_sha256": first.package.manifest_sha256,
            "provider": "claude",
            "exit_code": 0,
            "stdout_sha256": self.sha(b"old stdout"),
            "verdict": None,
        }
        (first.package.path / "audit.jsonl").write_text(
            json.dumps(source_audit, sort_keys=True) + "\n"
        )
        receipt = self.terminal_receipt(source_package=first.package)
        transport = dict(first.transport_identity)
        second = self.runtime.preview_retry(
            self.part,
            self.request,
            first.package.path,
            receipt,
            transport,
            max_attempts=2,
        )
        self.assertEqual(second.attempt, 2)
        result = self.runtime.run_retry(
            self.part,
            self.request,
            second,
            approved_retry_manifest_sha256=second.manifest_sha256,
            trusted_partition_enabled=True,
        )
        self.assertEqual((result.status, result.verdict), ("completed", "pass"))


if __name__ == "__main__":
    unittest.main()
