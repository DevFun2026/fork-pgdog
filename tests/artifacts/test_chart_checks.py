from copy import deepcopy
from pathlib import Path
import importlib
import sys
import unittest
import yaml

from test_chart import ROOT, CHART, BASE, CONFIG, helm_render


class RenderedChartValidationTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / "scripts/artifacts/chart_checks.py"
        self.assertTrue(path.is_file(), "rendered chart/TOML validator has not been implemented")
        sys.path.insert(0, str(ROOT / "scripts"))
        self.validate = importlib.import_module("artifacts.chart_checks").validate_rendered_chart
        self.values = yaml.safe_load((CHART / "values.yaml").read_text())
        self.values["config"].update(BASE["config"])
        self.values["users"].update(BASE["users"])
        result = helm_render(BASE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.docs = list(yaml.safe_load_all(result.stdout))

    def test_aligned_config_and_manifests_pass(self):
        self.validate(self.docs, self.values)

    def test_strict_read_policy_requires_matching_args_mount_and_key(self):
        values = deepcopy(self.values)
        values["queryPolicy"] = "strict-read"
        values["readPolicy"] = {"existingConfigMap": "pgdog-read-policy"}
        result = helm_render({**BASE, **values})
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = list(yaml.safe_load_all(result.stdout))
        self.validate(docs, values)

        cases = [
            (lambda pod: pod["initContainers"][0]["args"].remove("strict-read"), "query-policy"),
            (lambda pod: pod["containers"][0]["volumeMounts"].pop(), "read-policy"),
            (lambda pod: pod["volumes"].append(deepcopy(next(v for v in pod["volumes"] if v["name"] == "read-policy"))), "read-policy"),
            (lambda pod: next(v for v in pod["volumes"] if v["name"] == "read-policy")
             ["configMap"]["items"].clear(), "read-policy.toml"),
        ]
        for mutate, diagnostic in cases:
            with self.subTest(diagnostic=diagnostic):
                changed = deepcopy(docs)
                pod = next(d for d in changed if d["kind"] == "Deployment")["spec"]["template"]["spec"]
                mutate(pod)
                with self.assertRaisesRegex(ValueError, diagnostic):
                    self.validate(changed, values)

    def test_unrestricted_mode_rejects_read_policy_intent_and_artifacts(self):
        values = deepcopy(self.values)
        values["queryPolicy"] = "unrestricted"
        values["readPolicy"] = {"existingConfigMap": "pgdog-read-policy"}
        with self.assertRaisesRegex(ValueError, "readPolicy"):
            self.validate(self.docs, values)

    def test_toml_errors_and_port_mismatch_fail(self):
        for config, diagnostic in [("[invalid", "TOML"),
                                   (CONFIG.replace("port = 6432", "port = 6543"), "containerPort"),
                                   (CONFIG.replace("9090", "9999"), "healthcheckPort"),
                                   (CONFIG.replace('"0.0.0.0"', '"127.0.0.1"'), "host")]:
            with self.subTest(diagnostic=diagnostic):
                values = deepcopy(self.values)
                values["config"]["pgdogToml"] = config
                with self.assertRaisesRegex(ValueError, diagnostic):
                    self.validate(self.docs, values)

    def test_drain_must_fit_pod_grace(self):
        self.values["terminationGracePeriodSeconds"] = 120
        with self.assertRaisesRegex(ValueError, "grace"):
            self.validate(self.docs, self.values)

    def test_drain_requires_finite_termination_bound(self):
        self.values["config"]["pgdogToml"] = CONFIG.replace("shutdown_termination_timeout = 10000", "")
        with self.assertRaisesRegex(ValueError, "shutdown_termination_timeout"):
            self.validate(self.docs, self.values)

    def test_inline_credentials_are_rejected_without_disclosing_values(self):
        self.values["config"]["pgdogToml"] = CONFIG + '\n[admin]\npassword = "do-not-disclose"\n'
        with self.assertRaises(ValueError) as caught:
            self.validate(self.docs, self.values)
        self.assertIn("existingSecret", str(caught.exception))
        self.assertNotIn("do-not-disclose", str(caught.exception))

    def test_tls_secret_file_path_is_allowed_as_configuration(self):
        values = deepcopy(self.values)
        values["tls"]["existingSecret"] = "pgdog-tls"
        values["config"]["pgdogToml"] = CONFIG.replace('host = "0.0.0.0"', 'host = "0.0.0.0"\ntls_private_key = "/etc/pgdog/tls/tls.key"\ntls_certificate = "/etc/pgdog/tls/tls.crt"')
        rendered = helm_render({"config": values["config"], "users": values["users"], "tls": values["tls"]})
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        self.validate(list(yaml.safe_load_all(rendered.stdout)), values)

    def test_privilege_and_extra_exposure_mutations_fail(self):
        for mutate, diagnostic in [
            (lambda docs: docs[2]["spec"]["template"]["spec"]["containers"][0]["securityContext"].update({"runAsUser": 0}), "non-root"),
            (lambda docs: docs.append({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "leak"}}), "Secret"),
            (lambda docs: next(d for d in docs if d["kind"] == "Service")["spec"]["ports"].append({"port": 9090}), "Service")]:
            with self.subTest(diagnostic=diagnostic):
                docs = deepcopy(self.docs)
                # Helm output ordering is not the contract: locate Deployment explicitly.
                if diagnostic == "non-root":
                    next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]["securityContext"]["runAsUser"] = 0
                else:
                    mutate(docs)
                with self.assertRaisesRegex(ValueError, diagnostic):
                    self.validate(docs, self.values)


if __name__ == "__main__":
    unittest.main()
