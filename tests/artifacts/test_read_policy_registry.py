"""Version selection and provenance checks for strict-read catalog tooling."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load_script(name):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.replace(".py", ""), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReadPolicyRegistrySelectionTests(unittest.TestCase):
    def test_pin_and_output_path_are_selected_by_supported_major(self):
        registry = load_script("read_policy_registry.py")
        fixture = load_script("strict_read_fixture.py")
        with patch.dict(registry.PIN_SOURCES, {18: ROOT / "tests/artifacts/kubernetes/postgres.yaml"}), \
             patch.dict(fixture.PIN_SOURCES, {18: ROOT / "tests/artifacts/kubernetes/postgres.yaml"}):
            self.assertEqual(registry.pinned_image(18),
                             "postgres:18@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722")
            self.assertTrue(registry.registry_path(12).name.endswith("registry-pg12.json"))
            self.assertEqual(fixture.pinned_postgres_image(18), registry.pinned_image(18))

    def test_unknown_major_is_rejected_in_registry_and_fixture_helpers(self):
        registry = load_script("read_policy_registry.py")
        fixture = load_script("strict_read_fixture.py")
        for function in (registry.registry_path, registry.pinned_image,
                         fixture.pinned_postgres_image):
            with self.subTest(function=function.__name__):
                with self.assertRaisesRegex(ValueError, "12 or 18"):
                    function(13)

    def test_registry_major_must_be_an_exact_supported_integer(self):
        registry = load_script("read_policy_registry.py")
        for major in (12.0, 18.0, True, False, "12"):
            with self.subTest(major=major):
                with self.assertRaisesRegex(ValueError, "12 or 18"):
                    registry.validate_major(major)

    def test_catalog_oids_reject_boolean_and_fractional_numbers_but_keep_decimal_strings(self):
        registry = load_script("read_policy_registry.py")
        self.assertEqual(registry.row_oids("pg_type", [{"oid": "23"}]), [23])
        for value in (True, 23.5, 23.0, "23.0"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "malformed pg_type OID"):
                    registry.row_oids("pg_type", [{"oid": value}])

    def test_pg18_legacy_full_reference_can_seed_without_added_provenance(self):
        registry = load_script("read_policy_registry.py")
        legacy_reference = json.loads(registry.registry_path(18).read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference_path = root / "reference-pg18.json"
            reference_path.write_text(json.dumps(legacy_reference))
            output_path = root / "candidate-pg18.json"
            with patch.dict(registry.PIN_SOURCES, {18: ROOT / "tests/artifacts/kubernetes/postgres.yaml"}):
                registry.seed_candidates(reference_path, output_path, 18)
            seeded = json.loads(output_path.read_text())
        self.assertEqual(set(seeded), {"postgres_major", "source_image", "tables"})
        self.assertEqual(seeded["postgres_major"], 18)
        self.assertEqual(seeded["source_image"], legacy_reference["source_image"])
        self.assertEqual(set(seeded["tables"]), set(registry.TABLES))

    def test_pin_lookup_fails_closed_for_missing_or_ambiguous_major(self):
        registry = load_script("read_policy_registry.py")
        fixture = load_script("strict_read_fixture.py")
        for module, function in ((registry, registry.pinned_image),
                                 (fixture, fixture.pinned_postgres_image)):
            with self.subTest(module=module.__name__):
                with tempfile.TemporaryDirectory() as directory:
                    pin_file = Path(directory) / "postgres.yaml"
                    pin_file.write_text("image: postgres:18@sha256:" + "a" * 64 + "\n")
                    with patch.dict(module.PIN_SOURCES, {12: pin_file}):
                        with self.assertRaisesRegex((ValueError, RuntimeError), "12"):
                            function(12)
                        pin_file.write_text("\n".join([
                            "image: postgres:12@sha256:" + "a" * 64,
                            "image: postgres:12@sha256:" + "b" * 64,
                        ]))
                        with patch.dict(module.PIN_SOURCES, {12: pin_file}):
                            with self.assertRaisesRegex((ValueError, RuntimeError), "ambiguous"):
                                function(12)

    def test_pg12_seed_requires_provenance_and_fails_closed_on_incomplete_dependency_closure(self):
        registry = load_script("read_policy_registry.py")
        image = "postgres:12.22-bookworm@sha256:" + "c" * 64
        reference = {
            "postgres_major": 12,
            "source_image": image,
            "server_version": "12.22",
            "server_version_num": 120022,
            "platform": "linux/arm64",
            "capture_id": "fixture-capture-001",
            "tables": {name: [] for name in registry.TABLES},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = root / "postgres.yaml"
            pin.write_text("image: " + image + "\n")
            reference_path = root / "reference.json"
            reference_path.write_text(json.dumps(reference))
            output = root / "registry-pg12.json"
            with patch.dict(registry.PIN_SOURCES, {12: pin}):
                with self.assertRaisesRegex(ValueError, "dependency OIDs"):
                    registry.seed_candidates(reference_path, output, 12)
            self.assertFalse(output.exists())

            reference.pop("capture_id")
            reference_path.write_text(json.dumps(reference))
            with self.assertRaisesRegex(ValueError, "provenance"):
                with patch.dict(registry.PIN_SOURCES, {12: pin}):
                    registry.seed_candidates(reference_path, root / "invalid.json", 12)

    def test_refresh_rejects_platform_and_server_mismatch_but_records_new_capture_identity(self):
        registry = load_script("read_policy_registry.py")
        image = "postgres:12.22-bookworm@sha256:" + "d" * 64
        provenance = {
            "postgres_major": 12,
            "source_image": image,
            "server_version": "12.22",
            "server_version_num": 120022,
            "platform": "linux/amd64",
            "capture_id": "fixture-capture-002",
            "tables": {name: [] for name in registry.TABLES},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = root / "postgres.yaml"
            pin.write_text("image: " + image + "\n")
            expected_path = root / "registry-pg12.json"
            expected_path.write_text(json.dumps(provenance))
            capture_path = root / "capture.json"
            output = root / "out.json"
            for key, value in (("platform", "linux/arm64"),
                               ("server_version", "18.1"),
                               ("server_version_num", 180001)):
                capture = dict(provenance)
                capture[key] = value
                capture_path.write_text(json.dumps(capture))
                with self.subTest(field=key):
                    with patch.dict(registry.PIN_SOURCES, {12: pin}), \
                         patch.object(registry, "registry_path", return_value=expected_path):
                        with self.assertRaises(ValueError):
                            registry.refresh(capture_path, output, 12)

            capture = dict(provenance, capture_id="fixture-capture-999")
            capture_path.write_text(json.dumps(capture))
            with patch.dict(registry.PIN_SOURCES, {12: pin}), \
                 patch.object(registry, "registry_path", return_value=expected_path):
                registry.refresh(capture_path, output, 12)
            saved = json.loads(output.read_text())
            self.assertEqual(saved["reference_capture_id"], "fixture-capture-002")
            self.assertEqual(saved["capture_id"], "fixture-capture-999")

    def test_duplicate_catalog_oids_fail_closed_during_reference_and_capture_validation(self):
        registry = load_script("read_policy_registry.py")
        image = "postgres:12.22-bookworm@sha256:" + "e" * 64
        malformed = {
            "postgres_major": 12,
            "source_image": image,
            "server_version": "12.22",
            "server_version_num": 120022,
            "platform": "linux/arm64",
            "capture_id": "fixture-capture-duplicate",
            "tables": {name: [] for name in registry.TABLES},
        }
        malformed["tables"]["pg_type"] = [{"oid": "23"}, {"oid": "23"}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = root / "postgres-pg12.yaml"
            pin.write_text("image: " + image + "\n")
            reference_path = root / "reference.json"
            reference_path.write_text(json.dumps(malformed))
            output = root / "registry-pg12.json"
            with patch.dict(registry.PIN_SOURCES, {12: pin}):
                with self.assertRaisesRegex(ValueError, "duplicate pg_type OIDs"):
                    registry.seed_candidates(reference_path, output, 12)
            expected_path = root / "expected.json"
            expected_path.write_text(json.dumps({**malformed, "tables": {
                name: [] for name in registry.TABLES
            }}))
            with patch.dict(registry.PIN_SOURCES, {12: pin}), \
                 patch.object(registry, "registry_path", return_value=expected_path):
                with self.assertRaisesRegex(ValueError, "duplicate pg_type OIDs"):
                    registry.refresh(reference_path, output, 12)

    def test_pg18_legacy_capture_shape_refreshes_without_inventing_provenance(self):
        registry = load_script("read_policy_registry.py")
        original_path = registry.registry_path(18)
        original = json.loads(original_path.read_text())
        capture = dict(original)
        with tempfile.TemporaryDirectory() as directory:
            capture_path = Path(directory) / "capture.json"
            output_path = Path(directory) / "registry.json"
            capture_path.write_text(json.dumps(capture))
            registry.refresh(capture_path, output_path, 18)
            saved = json.loads(output_path.read_text())
        self.assertEqual(set(saved), {"postgres_major", "source_image", "tables"})
        self.assertEqual(saved, original)

    def test_pg18_legacy_refresh_still_binds_major_and_immutable_image(self):
        registry = load_script("read_policy_registry.py")
        original = json.loads(registry.registry_path(18).read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture_path, output_path = root / "capture.json", root / "out.json"
            for field, value in (("postgres_major", 12),
                                 ("postgres_major", 18.0),
                                 ("source_image", "postgres:18@sha256:" + "f" * 64)):
                capture_path.write_text(json.dumps(dict(original, **{field: value})))
                with self.subTest(field=field):
                    with self.assertRaisesRegex(ValueError, "major|image pin"):
                        registry.refresh(capture_path, output_path, 18)

    def test_pg18_partial_optional_provenance_is_rejected(self):
        registry = load_script("read_policy_registry.py")
        original = json.loads(registry.registry_path(18).read_text())
        capture = dict(original, server_version="18.0")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture_path = root / "capture.json"
            output_path = root / "registry.json"
            capture_path.write_text(json.dumps(capture))
            with self.assertRaisesRegex(ValueError, "provenance"):
                registry.refresh(capture_path, output_path, 18)


if __name__ == "__main__":
    unittest.main()
