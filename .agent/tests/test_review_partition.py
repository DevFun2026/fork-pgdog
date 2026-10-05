from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from agent_cli.review.models import ReviewPackageRequest
from agent_cli.review.package import ReviewPackageBlocked, package_usage
from agent_cli.review.partition import (
    build_partition,
    load_partition,
    partition_usage,
)

REGISTRY_PATH = (
    "applications/pgdog/pgdog/src/backend/schema/read_policy/registry-pg18.json"
)


class PartitionedReviewTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.git("init", "-b", "main")
        self.git("config", "user.email", "fixture@example.com")
        self.git("config", "user.name", "Fixture")
        self.write(".gitignore", ".agent/.runs/\n")
        self.write("README.md", "initial\n")
        self.write("docs/integration-contract.md", "Review cross-file contracts.\n")
        self.git("add", ".")
        self.git("commit", "-m", "initial")

    def tearDown(self):
        self.tempdir.cleanup()

    def git(self, *args):
        subprocess.run(("git", *args), cwd=self.root, check=True, capture_output=True)

    def write(self, path: str, content: str):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def commit_changes(self):
        self.git("add", ".")
        self.git("commit", "-m", "change")

    def request(self, **changes):
        values = {
            "root": self.root,
            "base": "HEAD~1",
            "head": "HEAD",
            "author_provider": "gemini",
            "reviewer_provider": "claude",
            "context_paths": (),
            "requirements": "Review the complete change for correctness and security.",
            "verification": {"checks": "fresh"},
            "max_package_bytes": 500_000,
            "max_estimated_tokens": 96_000,
        }
        values.update(changes)
        return ReviewPackageRequest(**values)

    def build(
        self,
        *,
        target_bytes=6_000,
        max_aggregate_bytes=100_000,
        max_aggregate_tokens=100_000,
        **kwargs,
    ):
        return build_partition(
            self.request(),
            max_aggregate_bytes=max_aggregate_bytes,
            max_aggregate_tokens=max_aggregate_tokens,
            target_bytes=target_bytes,
            integration_context_paths=("docs/integration-contract.md",),
            **kwargs,
        )

    def test_partition_reconstructs_exact_diff_and_covers_registry_records(self):
        rows = [
            {"oid": str(index), "name": "record-" + str(index), "detail": "x" * 96}
            for index in range(30)
        ]
        registry = json.dumps(
            {
                "postgres_major": 18,
                "source_image": "postgres:18",
                "tables": {"pg_type": rows},
            },
            separators=(",", ":"),
        )
        self.write(REGISTRY_PATH, registry)
        self.commit_changes()

        partition = self.build()

        self.assertGreater(len(partition.children), 1)
        rebuilt = b"".join(child.diff_bytes for child in partition.children)
        self.assertEqual(rebuilt, partition.root_package.diff_bytes)
        records = [
            span
            for child in partition.manifest["children"]
            for span in child["ranges"]
            if span["kind"] == "registry-records"
        ]
        self.assertEqual(
            sum(item["count"] for span in records for item in span["records"]), 30
        )
        spans = [item for span in records for item in span["records"]]
        self.assertEqual({item["table"] for item in spans}, {"pg_type"})
        self.assertLess(len(spans), 30)
        self.assertTrue(
            all(
                item["last_row"] - item["first_row"] + 1 == item["count"]
                for item in spans
            )
        )
        self.assertTrue(all(item["end"] > item["start"] for item in spans))
        self.assertTrue(
            all(span["record_end"] > span["record_start"] for span in records)
        )
        self.assertTrue(
            all(child.manifest.full_diff_sha256 is None for child in partition.children)
        )
        self.assertEqual(
            partition.manifest["integration_context_paths"],
            ["docs/integration-contract.md"],
        )
        self.assertEqual(partition.manifest["child_context_paths"], [])
        for child in partition.children:
            self.assertNotIn(
                "docs/integration-contract.md",
                {item.path for item in child.manifest.files},
            )
            self.assertLessEqual(package_usage(child)["bytes"], 6_000)
            self.assertLessEqual(package_usage(child)["estimated_tokens"], 96_000)
        self.assertGreaterEqual(
            partition_usage(partition)["bytes"],
            int(partition.manifest["aggregate_usage"]["bytes"]),
        )
        self.assertEqual(
            load_partition(partition.root_package.path, root=self.root).manifest,
            partition.manifest,
        )

        second = self.build()
        self.assertEqual(
            [entry["ranges"] for entry in partition.manifest["children"]],
            [entry["ranges"] for entry in second.manifest["children"]],
        )
        self.assertEqual(
            [child.diff_bytes for child in partition.children],
            [child.diff_bytes for child in second.children],
        )

    def test_oversized_ordinary_patch_is_blocked_instead_of_split(self):
        self.write("src/ordinary.txt", "x" * 8_000 + "\n")
        self.commit_changes()

        with self.assertRaisesRegex(ReviewPackageBlocked, "indivisible"):
            self.build()

    def test_oversized_indivisible_registry_record_is_blocked(self):
        self.write(
            REGISTRY_PATH,
            json.dumps(
                {
                    "postgres_major": 18,
                    "tables": {"pg_type": [{"oid": "1", "value": "x" * 8_000}]},
                },
                separators=(",", ":"),
            ),
        )
        self.commit_changes()

        with self.assertRaisesRegex(ReviewPackageBlocked, "record exceeds"):
            self.build()

    def test_registry_with_unknown_shape_or_custom_path_is_not_record_split(self):
        self.write(
            REGISTRY_PATH,
            json.dumps(
                {
                    "postgres_major": 18,
                    "padding": "x" * 9_000,
                    "tables": {"pg_type": [1]},
                },
                separators=(",", ":"),
            ),
        )
        self.commit_changes()
        with self.assertRaisesRegex(
            ReviewPackageBlocked, "records must be JSON objects"
        ):
            self.build()

        self.write(
            "src/registry-pg18.json",
            '{"tables":{"pg_type":[' + json.dumps({"x": "z" * 9_000}) + "]}}",
        )
        self.commit_changes()
        with self.assertRaisesRegex(
            ReviewPackageBlocked, "ordinary changed-file patch"
        ):
            self.build()

    def test_empty_integration_context_is_blocked(self):
        self.write("src/change.txt", "change\n")
        self.commit_changes()

        with self.assertRaisesRegex(ReviewPackageBlocked, "integration context"):
            build_partition(
                self.request(),
                max_aggregate_bytes=100_000,
                max_aggregate_tokens=100_000,
                target_bytes=500,
                integration_context_paths=(),
            )

    def test_binary_pinned_registry_is_not_record_split(self):
        target = self.root / REGISTRY_PATH
        target.parent.mkdir(parents=True)
        target.write_bytes(b"x" * 8_000 + b"\x00suffix")
        self.commit_changes()

        with self.assertRaisesRegex(ReviewPackageBlocked, "binary file"):
            self.build()

    def test_aggregate_usage_includes_reserved_integration_payload(self):
        self.write("src/change.txt", "change\n")
        self.commit_changes()

        partition = self.build()

        usage = partition_usage(partition)
        self.assertGreaterEqual(usage["integration_reserved_bytes"], 6_000)
        self.assertGreaterEqual(
            usage["bytes"],
            usage["root_bytes"]
            + usage["children_bytes"]
            + usage["integration_reserved_bytes"],
        )

    def test_aggregate_byte_and_token_limits_include_the_integration_reserve(self):
        self.write("src/change.txt", "change\n")
        self.commit_changes()
        first = self.build()
        usage = partition_usage(first)

        with self.assertRaisesRegex(
            ReviewPackageBlocked, "aggregate byte or token budget"
        ):
            self.build(max_aggregate_bytes=usage["bytes"] - 100)
        with self.assertRaisesRegex(
            ReviewPackageBlocked, "aggregate byte or token budget"
        ):
            self.build(max_aggregate_tokens=usage["estimated_tokens"] - 10)

    def test_loader_rejects_tampered_partition_manifest_and_unlisted_child_file(self):
        self.write("src/change.txt", "change\n")
        self.commit_changes()
        partition = self.build()

        manifest_path = partition.root_package.path / "partition.json"
        original = manifest_path.read_bytes()
        json.loads(original)
        invalid_manifests = []
        changed_start = json.loads(original)
        changed_start["children"][0]["ranges"][0]["start"] += 1
        invalid_manifests.append(changed_start)
        missing_range = json.loads(original)
        missing_range["children"][0]["ranges"].pop()
        invalid_manifests.append(missing_range)
        duplicate_range = json.loads(original)
        duplicate_range["children"][0]["ranges"].append(
            dict(duplicate_range["children"][0]["ranges"][0])
        )
        invalid_manifests.append(duplicate_range)
        duplicate_child = json.loads(original)
        duplicate_child["children"].append(dict(duplicate_child["children"][0]))
        invalid_manifests.append(duplicate_child)
        reordered = json.loads(original)
        if len(reordered["children"]) > 1:
            reordered["children"].reverse()
            invalid_manifests.append(reordered)
        for payload in invalid_manifests:
            manifest_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ReviewPackageBlocked):
                load_partition(partition.root_package.path, root=self.root)

        manifest_path.write_bytes(original)
        (partition.children[0].path / "diff.patch").write_bytes(b"tampered")
        with self.assertRaises(ReviewPackageBlocked):
            load_partition(partition.root_package.path, root=self.root)
        (partition.children[0].path / "diff.patch").write_bytes(
            partition.root_package.diff_bytes[
                partition.manifest["children"][0]["ranges"][0][
                    "start"
                ] : partition.manifest["children"][0]["ranges"][-1]["end"]
            ]
        )
        (partition.children[0].path / "unexpected.txt").write_text("extra")
        with self.assertRaisesRegex(ReviewPackageBlocked, "unlisted"):
            load_partition(partition.root_package.path, root=self.root)

    def test_loader_rejects_symlinked_child_payload(self):
        self.write("src/change.txt", "change\n")
        self.commit_changes()
        partition = self.build()
        child = partition.children[0]
        target = child.path / "requirements.md"
        original = target.read_bytes()
        target.unlink()
        outside = self.root / "outside.txt"
        outside.write_bytes(original)
        target.symlink_to(outside)

        with self.assertRaises(ReviewPackageBlocked):
            load_partition(partition.root_package.path, root=self.root)


if __name__ == "__main__":
    unittest.main()
