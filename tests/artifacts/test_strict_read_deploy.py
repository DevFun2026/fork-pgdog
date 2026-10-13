"""Tests for local-only paired strict-read/write deployment preparation."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts/generate-strict-read-deploy.py"
EXAMPLE = ROOT / "charts/fork-pgdog/examples/strict-read/icondo/operator-input.example.json"


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_strict_read_deploy", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_input(major=12):
    return {
        "namespace": "database",
        "kube_context": "validation-only-context",
        "postgres_major_version": major,
        "database_name": "icondo",
        "database_alias": "icondo",
        "protected_relations": ["public.synthetic_items", "billing.synthetic_events"],
        "schema_revision": "validation-only-epoch",
        "image_repository": "ghcr.io/devfun2026/fork-pgdog",
        "image_digest": "sha256:" + "a" * 64,
        "users_secret": "pgdog-users",
        "client_tls_secret": "pgdog-client-tls",
        "backend_ca_filename": "backend-ca.pem",
        "read_policy_configmap": "pgdog-read-policy",
        "backend_host": "staging-postgres.database.svc.cluster.local",
        "backend_port": 5432,
    }


class StrictReadDeployGeneratorTests(unittest.TestCase):
    def run_generator(self, data):
        temp = tempfile.TemporaryDirectory(prefix="strict-read-deploy-test-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        input_path, output_path = root / "operator.json", root / "generated"
        input_path.write_text(json.dumps(data))
        result = subprocess.run([sys.executable, str(GENERATOR), "--input", str(input_path),
                                 "--output", str(output_path)], text=True, capture_output=True)
        return result, output_path

    def test_postgres_12_and_18_generate_paired_policy_values(self):
        for major in (12, 18):
            with self.subTest(major=major):
                result, output = self.run_generator(valid_input(major))
                self.assertEqual(result.returncode, 0, result.stderr)
                import yaml
                read_values = yaml.safe_load((output / "read-values.yaml").read_text())
                write_values = yaml.safe_load((output / "write-values.yaml").read_text())
                self.assertEqual(read_values["queryPolicy"], "strict-read")
                self.assertIn("readPolicy", read_values)
                self.assertEqual(write_values["queryPolicy"], "unrestricted")
                self.assertNotIn("readPolicy", write_values)

    def test_boolean_and_unsupported_postgres_majors_are_rejected(self):
        generator = load_generator()
        for major in (True, False, 11, 13, 17, 19, "12"):
            with self.subTest(major=major):
                with self.assertRaisesRegex(ValueError, "integer 12 or 18"):
                    generator.validate(valid_input(major))

    def test_inputs_keep_tls_image_and_passthrough_credentials_fail_closed(self):
        generator = load_generator()
        base = valid_input()
        for field, value, diagnostic in (
            ("image_digest", "sha256:latest", "immutable sha256"),
            ("client_tls_secret", "<REQUIRED_TLS_SECRET>", "non-placeholder"),
            ("backend_ca_filename", "<REQUIRED_BACKEND_CA>", "non-placeholder"),
        ):
            with self.subTest(field=field):
                data = dict(base, **{field: value})
                with self.assertRaisesRegex(ValueError, diagnostic):
                    generator.validate(data)
        with self.assertRaisesRegex(ValueError, "unsupported input keys"):
            generator.validate(dict(base, application_password="must-not-be-stored"))
        host, port = generator.validate(base)
        read_values = generator.render(base, host, port, "strict-read")
        write_values = generator.render(base, host, port, "unrestricted")
        for values in (read_values, write_values):
            config = values["config"]["pgdogToml"]
            self.assertIn('passthrough_auth = "enabled"', config)
            self.assertIn("tls_client_required = true", config)
            self.assertIn('tls_verify = "verify_full"', config)
            self.assertNotIn("password", config.lower())
            self.assertEqual(values["users"], {"existingSecret": "pgdog-users"})

    def test_missing_required_inputs_and_unsafe_backend_host_are_rejected(self):
        missing, _ = self.run_generator({})
        self.assertEqual(missing.returncode, 2)
        self.assertIn("missing required inputs", missing.stderr)
        unsafe = valid_input()
        unsafe["backend_host"] = "db.example;drop table"
        result, _ = self.run_generator(unsafe)
        self.assertEqual(result.returncode, 2)
        self.assertIn("DNS hostname", result.stderr)

    def test_icondo_example_has_required_operator_placeholders_and_no_credentials(self):
        data = json.loads(EXAMPLE.read_text())
        self.assertEqual(data["namespace"], "database")
        self.assertEqual(data["postgres_major_version"], 12)
        self.assertEqual(data["database_name"], "icondo")
        self.assertEqual(data["database_alias"], "icondo")
        self.assertEqual(data["backend_host"], "staging-postgres.database.svc.cluster.local")
        self.assertEqual(data["backend_port"], 5432)
        for field in ("kube_context", "image_digest", "backend_ca_filename", "schema_revision"):
            with self.subTest(field=field):
                self.assertRegex(data[field], r"[<>]|REPLACE_ME|CHANGEME")
        self.assertTrue(all("<" in relation for relation in data["protected_relations"]))
        self.assertNotIn("password", json.dumps(data).lower())
        result, _ = self.run_generator(data)
        self.assertEqual(result.returncode, 2)
        self.assertIn("non-placeholder string", result.stderr)

    @unittest.skipUnless(shutil.which("helm"), "Helm is unavailable")
    def test_both_generated_policies_pass_real_chart_validator_with_synthetic_values(self):
        result, output = self.run_generator(valid_input(12))
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("read-values.yaml", "write-values.yaml"):
            check = subprocess.run([sys.executable, str(ROOT / "scripts/verify-artifacts"), "chart",
                                    "--chart", str(ROOT / "charts/fork-pgdog"), "--values",
                                    str(output / name)], text=True, capture_output=True)
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)


if __name__ == "__main__":
    unittest.main()
