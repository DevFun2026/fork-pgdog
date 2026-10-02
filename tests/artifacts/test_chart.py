"""Exercise chart output and schema through Helm, not template source text."""
from copy import deepcopy
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts/fork-pgdog"
CONFIG = '''[general]
host = "0.0.0.0"
port = 6432
healthcheck_port = 9090
shutdown_timeout = 120000
shutdown_termination_timeout = 10000

[[databases]]
name = "pgdog"
host = "postgres.example.internal"
'''
BASE = {"config": {"pgdogToml": CONFIG}, "users": {"existingSecret": "fixture-users"}}


def helm_render(values):
    with tempfile.TemporaryDirectory(prefix="fork-chart-values-") as directory:
        path = Path(directory) / "values.yaml"
        path.write_text(yaml.safe_dump(values))
        return subprocess.run(["helm", "template", "test", str(CHART), "-f", str(path)],
                              text=True, capture_output=True)


class ChartTests(unittest.TestCase):
    def render(self, changes=None):
        self.assertTrue(CHART.is_dir(), "owned chart has not been implemented")
        values = deepcopy(BASE)
        values.update(changes or {})
        result = helm_render(values)
        self.assertEqual(result.returncode, 0, result.stderr)
        return [doc for doc in yaml.safe_load_all(result.stdout) if doc]

    def deployment(self, changes=None):
        return next(doc for doc in self.render(changes) if doc["kind"] == "Deployment")

    def test_default_runtime_is_hardened_and_secret_only(self):
        docs = self.render()
        self.assertEqual(sorted(doc["kind"] for doc in docs),
                         ["ConfigMap", "Deployment", "Service", "ServiceAccount"])
        workload = next(doc for doc in docs if doc["kind"] == "Deployment")
        pod = workload["spec"]["template"]["spec"]
        self.assertEqual(workload["spec"]["replicas"], 1)
        self.assertEqual(pod["terminationGracePeriodSeconds"], 150)
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertFalse(pod["enableServiceLinks"])
        self.assertEqual(pod["nodeSelector"]["kubernetes.io/os"], "linux")
        for container in pod["containers"] + pod["initContainers"]:
            self.assertEqual(container["image"], "ghcr.io/devfun2026/fork-pgdog:0.1.60")
            self.assertEqual(container["securityContext"], {
                "runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}})
            self.assertEqual(container["args"][:4], ["--config", "/etc/pgdog/config/pgdog.toml",
                                                     "--users", "/etc/pgdog/users/users.toml"])
            mounts = {mount["name"]: mount for mount in container["volumeMounts"]}
            self.assertTrue(mounts["config"]["readOnly"])
            self.assertTrue(mounts["users"]["readOnly"])
        self.assertEqual(pod["initContainers"][0]["args"][-1], "configcheck")
        volumes = {volume["name"]: volume for volume in pod["volumes"]}
        self.assertEqual(volumes["users"]["secret"]["secretName"], "fixture-users")
        self.assertEqual(volumes["tmp"]["emptyDir"]["sizeLimit"], "64Mi")
        self.assertIn("checksum/config", workload["spec"]["template"]["metadata"]["annotations"])
        service = next(doc for doc in docs if doc["kind"] == "Service")
        self.assertEqual(service["spec"]["type"], "ClusterIP")
        self.assertEqual(service["spec"]["ports"], [{"name": "pgsql", "port": 6432,
                                                    "targetPort": "pgsql", "protocol": "TCP"}])

    def test_probe_roles_and_custom_ports(self):
        pod = self.deployment({"containerPort": 6543, "healthcheckPort": 9191,
                               "service": {"port": 15432}})["spec"]["template"]["spec"]
        container = pod["containers"][0]
        self.assertEqual(container["startupProbe"]["tcpSocket"], {"port": "pgsql"})
        self.assertEqual(container["livenessProbe"]["tcpSocket"], {"port": "pgsql"})
        self.assertEqual(container["readinessProbe"]["httpGet"], {"path": "/", "port": "health"})
        self.assertEqual(container["ports"], [{"name": "pgsql", "containerPort": 6543, "protocol": "TCP"},
                                              {"name": "health", "containerPort": 9191, "protocol": "TCP"}])

    def test_digest_overrides_tag_in_both_containers(self):
        digest = "sha256:" + "a" * 64
        pod = self.deployment({"image": {"tag": "ignored", "digest": digest}})["spec"]["template"]["spec"]
        for container in pod["containers"] + pod["initContainers"]:
            self.assertEqual(container["image"], "ghcr.io/devfun2026/fork-pgdog@" + digest)

    def test_external_config_and_tls_modes_do_not_create_owned_config(self):
        for source, kind in [("existingConfigMap", "configMap"), ("existingSecret", "secret")]:
            with self.subTest(source=source):
                docs = self.render({"config": {"pgdogToml": "", source: "external-config"},
                                    "tls": {"existingSecret": "fixture-tls"}})
                self.assertNotIn("ConfigMap", [doc["kind"] for doc in docs])
                workload = next(doc for doc in docs if doc["kind"] == "Deployment")
                self.assertNotIn("checksum/config", workload["spec"]["template"]["metadata"].get("annotations", {}))
                pod = workload["spec"]["template"]["spec"]
                volumes = {volume["name"]: volume for volume in pod["volumes"]}
                self.assertIn(kind, volumes["config"])
                self.assertEqual(volumes["tls"]["secret"]["secretName"], "fixture-tls")
                for container in pod["containers"] + pod["initContainers"]:
                    tls = next(m for m in container["volumeMounts"] if m["name"] == "tls")
                    self.assertEqual(tls["mountPath"], "/etc/pgdog/tls")
                    self.assertTrue(tls["readOnly"])

    def test_metadata_cannot_change_selectors_and_config_changes_roll_pods(self):
        before = self.deployment()
        after = self.deployment({"podLabels": {"team": "platform"}, "podAnnotations": {"note": "test"},
                                 "config": {"pgdogToml": CONFIG + "\n# revised\n"}})
        self.assertEqual(before["spec"]["selector"], after["spec"]["selector"])
        self.assertNotEqual(before["spec"]["template"]["metadata"]["annotations"]["checksum/config"],
                            after["spec"]["template"]["metadata"]["annotations"]["checksum/config"])
        self.assertEqual(after["spec"]["template"]["metadata"]["labels"]["team"], "platform")

    def test_literal_config_is_preserved_without_template_execution(self):
        config = CONFIG + '\n# {{ fail "must-not-execute" }}\n'
        docs = self.render({"config": {"pgdogToml": config}})
        rendered = next(doc for doc in docs if doc["kind"] == "ConfigMap")["data"]["pgdog.toml"]
        self.assertEqual(rendered, config)

    def test_operator_overrides_and_external_service_opt_in(self):
        changes = {"replicaCount": 2, "resources": {"requests": {"cpu": "250m", "memory": "256Mi"}},
                   "imagePullSecrets": [{"name": "private-registry"}], "nodeSelector": {"pool": "database"},
                   "tolerations": [{"key": "database", "operator": "Exists", "effect": "NoSchedule"}],
                   "affinity": {"nodeAffinity": {"preferredDuringSchedulingIgnoredDuringExecution": []}},
                   "service": {"type": "LoadBalancer"}}
        docs = self.render(changes)
        pod = next(doc for doc in docs if doc["kind"] == "Deployment")["spec"]["template"]["spec"]
        self.assertEqual(pod["imagePullSecrets"], [{"name": "private-registry"}])
        self.assertEqual(pod["nodeSelector"], {"kubernetes.io/os": "linux", "pool": "database"})
        self.assertEqual(pod["containers"][0]["resources"]["requests"]["cpu"], "250m")
        self.assertEqual(next(doc for doc in docs if doc["kind"] == "Service")["spec"]["type"], "LoadBalancer")

    def test_invalid_inputs_fail_before_emitting_manifests(self):
        cases = [({}, "config"), ({"config": {"pgdogToml": CONFIG}}, "users"),
                 ({"config": {"pgdogToml": CONFIG, "existingConfigMap": "other"}, "users": BASE["users"]}, "config"),
                 ({**BASE, "image": {"digest": "sha256:bad"}}, "digest"),
                 ({**BASE, "replicaCount": 0}, "replicaCount"),
                 ({**BASE, "containerPort": 0}, "containerPort"),
                 ({**BASE, "healthcheckPort": 6432}, "port"),
                 ({**BASE, "users": {"existingSecret": "fixture-users", "password": "DO-NOT-EMIT"}}, "password"),
                 ({**BASE, "nodeSelector": {"kubernetes.io/os": "windows"}}, "nodeSelector"),
                 ({**BASE, "podLabels": {"app.kubernetes.io/instance": "different"}}, "app.kubernetes.io/instance"),
                 ({**BASE, "podAnnotations": {"checksum/config": "stale"}}, "checksum/config")]
        self.assertTrue(CHART.is_dir(), "owned chart has not been implemented")
        for values, diagnostic in cases:
            with self.subTest(diagnostic=diagnostic, values=values):
                result = helm_render(values)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(diagnostic.lower(), result.stderr.lower())
                self.assertNotIn("kind: Deployment", result.stdout)


if __name__ == "__main__":
    unittest.main()
