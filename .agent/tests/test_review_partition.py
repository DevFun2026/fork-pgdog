from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_cli.review.models import ReviewPackageRequest
from agent_cli.review.package import ReviewPackageBlocked, package_usage
from agent_cli.review.partition import (
    PARTITION_REVIEW_GUIDANCE,
    build_partition,
    load_partition,
    partition_usage,
)

REGISTRY_PATH = (
    "applications/pgdog/pgdog/src/backend/schema/read_policy/registry-pg18.json"
)
PROFILE_PATH = (
    "applications/pgdog/pgdog/src/backend/schema/read_policy/profiles/"
    "dependency-pg18-core.json"
)
CATALOGS = (
    "pg_aggregate", "pg_am", "pg_amop", "pg_amproc", "pg_cast",
    "pg_collation", "pg_enum", "pg_extension", "pg_namespace", "pg_opclass",
    "pg_operator", "pg_opfamily", "pg_proc", "pg_range", "pg_ts_config",
    "pg_ts_config_map", "pg_ts_dict", "pg_ts_parser", "pg_ts_template", "pg_type",
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

    def dependency_profile(self, *, major=18, extensions=(), rows=None, **overrides):
        document = {
            "format": "pgdog-read-dependency-profile/v2",
            "provenance": {
                "postgres_major": major,
                "source_image": {
                    12: "postgres:12.22-bookworm@sha256:2f2a8c2a7d10862e7fba2602e304523554f9df8244c632dafe2628ccb398fb5c",
                    18: "postgres:18@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722",
                }[major],
                "server_version": "12.22" if major == 12 else "18.6",
                "server_version_num": 120_022 if major == 12 else 180_006,
                "platform": "linux/arm64",
                "capture_id": f"fixture-pg{major}",
            },
            "enabled_extensions": list(extensions),
            "catalog": {table: [] for table in CATALOGS},
            "roots": [],
            "extensions": [
                {
                    "name": name,
                    "version": (
                        "1.4" if major == 12 and name == "pg_trgm" else
                        "1.5" if major == 12 else
                        "1.6" if name == "pg_trgm" else "1.8"
                    ),
                    "namespace": "public",
                    "members": [],
                    "derived_members": [],
                    "fields": {},
                }
                for name in extensions
            ],
            "module_sha256": {name: "a" * 64 for name in extensions},
            "client_functions": [],
            "projection_types": [],
            "namespace_authority": "actor-namespace-authority/v1",
        }
        document["catalog"]["pg_type"] = rows if rows is not None else []
        document.update(overrides)
        return json.dumps(document, separators=(",", ":"))

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

    def test_pg12_registry_partition_preserves_exact_bytes_and_path(self):
        path = REGISTRY_PATH.replace("pg18", "pg12")
        rows = [{"oid": str(index + 1), "detail": "x" * 96} for index in range(60)]
        self.write(path, json.dumps({"postgres_major": 12, "source_image": "postgres:12",
                                   "tables": {"pg_type": rows}}, separators=(",", ":")))
        self.commit_changes()
        partition = self.build()
        self.assertEqual(b"".join(child.diff_bytes for child in partition.children),
                         partition.root_package.diff_bytes)
        spans = [span for child in partition.manifest["children"] for span in child["ranges"]
                 if span["kind"] == "registry-records"]
        self.assertTrue(spans, "PG12 registry must split only at complete catalog records")
        self.assertEqual({span["path"] for span in spans}, {path})
        self.assertEqual(sum(record["count"] for span in spans for record in span["records"]), 60)
        self.assertEqual(load_partition(partition.root_package.path, root=self.root).manifest_sha256,
                         partition.manifest_sha256)
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

    def test_shared_context_budget_converges_for_large_partitioned_registry(self):
        rows = [
            {"oid": str(index), "name": "record-" + str(index), "detail": "x" * 220}
            for index in range(3_000)
        ]
        self.write(
            REGISTRY_PATH,
            json.dumps(
                {
                    "postgres_major": 18,
                    "source_image": "postgres:18",
                    "tables": {"pg_type": rows},
                },
                separators=(",", ":"),
            ),
        )
        self.write("src/resolve.rs", "r" * 28_851)
        self.write("src/rows.rs", "s" * 9_377)
        self.git("add", ".")
        self.git("commit", "-m", "registry and resolver changes")

        request = self.request(
            context_paths=("src/resolve.rs", "src/rows.rs"),
            max_package_bytes=500_000,
            max_estimated_tokens=96_000,
        )
        partition = build_partition(
            request,
            integration_context_paths=("docs/integration-contract.md",),
            max_aggregate_bytes=2_500_000,
            max_aggregate_tokens=800_000,
            target_bytes=250_000,
        )

        self.assertGreater(len(partition.children), 1)
        for child in partition.children:
            self.assertLessEqual(package_usage(child)["bytes"], 250_000)
            self.assertEqual(
                {item.path for item in child.manifest.files},
                {"src/resolve.rs", "src/rows.rs", "partition-scope.json"},
            )
            scope = json.loads(
                (child.path / "context" / "partition-scope.json").read_text()
            )
            self.assertEqual(scope["root_manifest_sha256"], partition.root_package.manifest_sha256)
            self.assertEqual(
                scope["full_diff_sha256"],
                partition.root_package.manifest.full_diff_sha256,
            )
            self.assertEqual(scope["head_sha"], partition.root_package.manifest.head_sha)
            self.assertEqual(scope["review_guidance"], PARTITION_REVIEW_GUIDANCE)
        self.assertLessEqual(partition_usage(partition)["bytes"], 2_500_000)

    def test_sizing_retry_repartitions_after_small_package_overage(self):
        for index in range(30):
            self.write(
                f"src/file-{index:02}.txt",
                f"{index:02}" + "x" * 550 + "\n",
            )
        self.git("add", ".")
        self.git("commit", "-m", "many indivisible changes")
        request = self.request(max_package_bytes=500_000, max_estimated_tokens=96_000)
        target_bytes = 20_000

        def measured_usage(child):
            diff_bytes = len(child.diff_bytes)
            if diff_bytes >= 15_000:
                # Model a package whose measured metadata/context makes it 9 B
                # over the invocation cap; smaller regrouped shards fit.
                package_bytes = target_bytes + 9
            else:
                package_bytes = diff_bytes + 4_600
            return {
                "bytes": package_bytes,
                "estimated_tokens": (package_bytes + 2) // 3,
            }

        with patch("agent_cli.review.partition.package_usage", side_effect=measured_usage):
            partition = build_partition(
                request,
                integration_context_paths=("docs/integration-contract.md",),
                max_aggregate_bytes=100_000,
                max_aggregate_tokens=100_000,
                target_bytes=target_bytes,
            )

        self.assertGreater(len(partition.children), 1)
        self.assertTrue(all(len(child.diff_bytes) < 15_000 for child in partition.children))
        self.assertTrue(all(package_usage(child)["bytes"] <= target_bytes for child in partition.children))

    def test_oversized_ordinary_patch_is_blocked_instead_of_split(self):
        self.write("src/ordinary.txt", "x" * 8_000 + "\n")
        self.commit_changes()

        with self.assertRaisesRegex(ReviewPackageBlocked, "indivisible"):
            self.build()

    def test_v2_dependency_profile_splits_at_catalog_records_and_reconstructs_exactly(self):
        rows = [
            {"identity": index, "fields": {"typname": "type-" + str(index), "padding": "x" * 200}}
            for index in sorted(range(1, 71), key=str)
        ]
        path = PROFILE_PATH
        self.write(path, self.dependency_profile(rows=rows))
        self.commit_changes()

        partition = self.build(target_bytes=10_000)

        self.assertGreater(len(partition.children), 1)
        self.assertEqual(b"".join(child.diff_bytes for child in partition.children), partition.root_package.diff_bytes)
        spans = [
            span for entry in partition.manifest["children"] for span in entry["ranges"]
            if span["kind"] == "profile-catalog-records"
        ]
        self.assertTrue(spans)
        self.assertEqual({span["path"] for span in spans}, {path})
        records = [record for span in spans for record in span["records"]]
        self.assertEqual(sum(record["count"] for record in records), len(rows))
        self.assertEqual({record["table"] for record in records}, {"pg_type"})
        for child in partition.children:
            self.assertLessEqual(package_usage(child)["bytes"], 10_000)
        self.assertEqual(
            load_partition(partition.root_package.path, root=self.root).manifest,
            partition.manifest,
        )

    def test_only_eight_exact_dependency_profile_names_can_be_split(self):
        cases = (
            (12, "core", ()),
            (12, "pg-trgm", ("pg_trgm",)),
            (12, "btree-gist", ("btree_gist",)),
            (12, "both", ("btree_gist", "pg_trgm")),
            (18, "core", ()),
            (18, "pg-trgm", ("pg_trgm",)),
            (18, "btree-gist", ("btree_gist",)),
            (18, "both", ("btree_gist", "pg_trgm")),
        )
        for major, selector, extensions in cases:
            with self.subTest(major=major, selector=selector):
                self.write("README.md", "initial\n")
                path = (
                    "applications/pgdog/pgdog/src/backend/schema/read_policy/profiles/"
                    f"dependency-pg{major}-{selector}.json"
                )
                rows = [{"identity": i, "fields": {"padding": "x" * 200}} for i in sorted(range(1, 71), key=str)]
                self.write(path, self.dependency_profile(major=major, extensions=extensions, rows=rows))
                self.commit_changes()
                partition = self.build(target_bytes=10_000)
                self.assertEqual(b"".join(child.diff_bytes for child in partition.children), partition.root_package.diff_bytes)
                self.assertTrue(any(
                    span["kind"] == "profile-catalog-records"
                    for child in partition.manifest["children"] for span in child["ranges"]
                ))

    def test_near_match_dependency_profile_path_is_not_record_split(self):
        path = PROFILE_PATH.replace("dependency-pg18-core.json", "dependency-pg18-core-copy.json")
        rows = [{"identity": 1, "fields": {"padding": "x" * 8_000}}]
        self.write(path, self.dependency_profile(rows=rows))
        self.commit_changes()
        with self.assertRaisesRegex(ReviewPackageBlocked, "ordinary changed-file patch"):
            self.build()

    def test_malformed_profile_envelope_provenance_selector_and_schema_are_not_split(self):
        valid_rows = [{"identity": 1, "fields": {"padding": "x" * 8_000}}]
        cases = (
            ("format", self.dependency_profile(rows=valid_rows, format="pgdog-read-dependency-profile/v1")),
            ("provenance", self.dependency_profile(rows=valid_rows, provenance={"postgres_major": 12})),
            (
                "image-major-prefix-collision",
                self.dependency_profile(
                    rows=valid_rows,
                    provenance={
                        "postgres_major": 18,
                        "source_image": "postgres:180@sha256:" + "a" * 64,
                        "server_version": "18.6",
                        "server_version_num": 180_006,
                        "platform": "linux/arm64",
                        "capture_id": "fixture-pg18",
                    },
                ),
            ),
            ("selector", self.dependency_profile(rows=valid_rows, enabled_extensions=["pg_trgm"])),
            ("schema", self.dependency_profile(rows=[{"identity": 1, "fields": "bad"}])),
            (
                "unhashable-root-catalog",
                self.dependency_profile(
                    rows=valid_rows,
                    roots=[{"catalog": [], "identity": 1}],
                ),
            ),
            (
                "unhashable-platform",
                self.dependency_profile(
                    rows=valid_rows,
                    provenance={
                        "postgres_major": 18,
                        "source_image": "postgres:18@sha256:" + "a" * 64,
                        "server_version": "18.6",
                        "server_version_num": 180_006,
                        "platform": {},
                        "capture_id": "fixture-pg18",
                    },
                ),
            ),
            (
                "nonstandard-json-number",
                self.dependency_profile(
                    rows=[{"identity": 1, "fields": {"name": "ok"}}]
                ).replace('"name":"ok"', '"name":NaN'),
            ),
        )
        for label, payload in cases:
            with self.subTest(label=label):
                self.write(PROFILE_PATH, payload)
                self.commit_changes()
                with self.assertRaises(ReviewPackageBlocked):
                    self.build()

    def test_small_dependency_profile_is_still_schema_validated(self):
        invalid = self.dependency_profile(
            rows=[{"identity": 1, "fields": {"name": "ok"}}],
            format="pgdog-read-dependency-profile/v1",
        )
        self.write(PROFILE_PATH, invalid)
        self.commit_changes()
        with self.assertRaisesRegex(ReviewPackageBlocked, "v2 envelope"):
            self.build()

    def test_dependency_profile_with_oversized_single_record_is_blocked(self):
        self.write(
            PROFILE_PATH,
            self.dependency_profile(rows=[{"identity": 1, "fields": {"padding": "x" * 8_000}}]),
        )
        self.commit_changes()
        with self.assertRaisesRegex(ReviewPackageBlocked, "indivisible.*record|record.*exceeds"):
            self.build()

    def test_dependency_profile_split_ranges_reject_tampering(self):
        rows = [{"identity": i, "fields": {"padding": "x" * 200}} for i in sorted(range(1, 71), key=str)]
        self.write(PROFILE_PATH, self.dependency_profile(rows=rows))
        self.commit_changes()
        partition = self.build(target_bytes=10_000)
        manifest_path = partition.root_package.path / "partition.json"
        original = manifest_path.read_bytes()
        changed = json.loads(original)
        changed["children"][0]["ranges"][0]["records"][0]["start"] += 1
        manifest_path.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaises(ReviewPackageBlocked):
            load_partition(partition.root_package.path, root=self.root)

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
