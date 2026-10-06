import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/strict-read-helm-smoke.sh"


class StrictReadSmokeIsolationTests(unittest.TestCase):
    def _run_isolated_harness(self, temp, *, kind_create_fails=False):
        fake_bin = temp / "bin"
        fake_bin.mkdir()
        calls = temp / "calls.jsonl"
        for name in ("docker", "kind", "kubectl", "helm"):
            path = fake_bin / name
            path.write_text(
                "#!/usr/bin/env python3\n"
                "import json,os,sys\n"
                "command=os.path.basename(sys.argv[0])\n"
                "with open(os.environ['CALL_LOG'],'a') as f: "
                "f.write(json.dumps([command,*sys.argv[1:]])+'\\n')\n"
                "if command=='kind' and sys.argv[1:2]==['create'] and os.environ.get('KIND_CREATE_FAIL')=='1': "
                "print('ERROR: cluster already exists',file=sys.stderr); sys.exit(1)\n"
                "if command=='kubectl' and 'apply' in sys.argv: sys.exit(1)\n"
            )
            path.chmod(0o755)
        existing = temp / "current-kubeconfig"
        existing.write_text("CURRENT USER CONFIG\n")
        baseline = temp / "baseline-pgdog"
        baseline.write_text("#!/bin/sh\necho \"error: unexpected argument '--query-policy' found\" >&2\nexit 2\n")
        baseline.chmod(0o755)
        env = dict(
            os.environ,
            PATH=str(fake_bin) + os.pathsep + os.environ["PATH"],
            KUBECONFIG=str(existing),
            CALL_LOG=str(calls),
            TMPDIR=str(temp),
            STRICT_READ_BASELINE_BIN=str(baseline),
            STRICT_READ_BASELINE_SOURCE_SHA="960942d4254a547d459d44545151f30380ae3173",
        )
        if kind_create_fails:
            env["KIND_CREATE_FAIL"] = "1"
        isolated_script = temp / "repo/scripts/strict-read-helm-smoke.sh"
        isolated_script.parent.mkdir(parents=True)
        shutil.copy2(SCRIPT, isolated_script)
        fixtures = temp / "repo/tests/artifacts/kubernetes"
        fixtures.mkdir(parents=True)
        for filename in ("postgres.yaml", "kind.yaml"):
            shutil.copy2(ROOT / "tests/artifacts/kubernetes" / filename, fixtures / filename)
        result = subprocess.run(
            ["bash", str(isolated_script), "--image", "fork-pgdog:strict-read-dev",
             "--chart", str(ROOT / "charts/fork-pgdog")],
            env=env,
            text=True,
            capture_output=True,
            timeout=30,
            cwd=temp,
        )
        recorded = [json.loads(line) for line in calls.read_text().splitlines()]
        return result, existing, recorded

    def test_owned_kind_failure_cleans_only_its_private_cluster(self):
        self.assertTrue(SCRIPT.is_file(), "paired strict-read smoke harness is missing")
        with tempfile.TemporaryDirectory(prefix="strict-read-smoke-isolation-") as directory:
            temp = Path(directory)
            result, existing, recorded = self._run_isolated_harness(temp)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertEqual(existing.read_text(), "CURRENT USER CONFIG\n")
            create = next(call for call in recorded if call[:2] == ["kind", "create"])
            cluster = create[create.index("--name") + 1]
            private = Path(create[create.index("--kubeconfig") + 1])
            self.assertTrue(cluster.startswith("fork-pgdog-strict-smoke-"))
            self.assertLessEqual(len(f"{cluster}-control-plane"), 64)
            self.assertNotEqual(private, existing)
            self.assertEqual(private.parent.parent, temp)
            kubectl_calls = [call for call in recorded if call[0] == "kubectl"]
            self.assertTrue(kubectl_calls)
            for call in kubectl_calls:
                self.assertEqual(call[call.index("--kubeconfig") + 1], str(private))
                self.assertEqual(call[call.index("--context") + 1], f"kind-{cluster}")
                self.assertEqual(call[call.index("--namespace") + 1], f"{cluster}-ns")
            self.assertIn(["kind", "delete", "cluster", "--name", cluster,
                           "--kubeconfig", str(private)], recorded)
            self.assertFalse(any(call[0] == "helm" for call in recorded))

    def test_kind_create_collision_does_not_delete_unowned_cluster(self):
        self.assertTrue(SCRIPT.is_file(), "paired strict-read smoke harness is missing")
        with tempfile.TemporaryDirectory(prefix="strict-read-smoke-collision-") as directory:
            result, existing, recorded = self._run_isolated_harness(
                Path(directory), kind_create_fails=True
            )
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertEqual(existing.read_text(), "CURRENT USER CONFIG\n")
            self.assertTrue(any(call[:2] == ["kind", "create"] for call in recorded))
            self.assertFalse(
                any(call[:3] == ["kind", "delete", "cluster"] for call in recorded),
                "failed Kind create must not delete a cluster it did not create",
            )

    def test_harness_has_two_policy_modes_and_immutable_rollout_checks(self):
        self.assertTrue(SCRIPT.is_file(), "paired strict-read smoke harness is missing")
        source = SCRIPT.read_text()
        for token in (
            "strict-read", "unrestricted", "pgdog-read", "pgdog-write",
            "read-policy.toml", "rollout restart",
            "strict-smoke-v1", "strict-smoke-v2", "schema_revision",
            "users = []",
        ):
            with self.subTest(token=token):
                self.assertIn(token, source)

    def test_native_artifact_and_full_quality_gates_require_the_smoke_inputs(self):
        build = (ROOT / "scripts/build-artifact").read_text()
        self.assertIn("strict-read-helm-smoke.sh", build)
        self.assertIn("STRICT_READ_BASELINE_SOURCE_SHA", build)
        artifact = yaml.load((ROOT / ".github/workflows/artifact-quality.yml").read_text(),
                             Loader=yaml.BaseLoader)
        self.assertEqual(set(artifact["on"]), {"pull_request", "workflow_dispatch"})
        self.assertEqual({(row["runner"], row["arch"]) for row in
                          artifact["jobs"]["build"]["strategy"]["matrix"]["include"]},
                         {("ubuntu-24.04", "amd64"), ("ubuntu-24.04-arm", "arm64")})
        uploads = [step["with"]["path"] for job in artifact["jobs"].values()
                   for step in job.get("steps", []) if "upload-artifact@" in step.get("uses", "")]
        self.assertTrue(any("strict-read-helm-smoke.json" in path for path in uploads))
        self.assertTrue(all(".agent" not in path for path in uploads))

        quality = yaml.load((ROOT / ".github/workflows/fork-quality.yml").read_text(),
                            Loader=yaml.BaseLoader)
        steps = quality["jobs"]["verification"]["steps"]
        pull = next(index for index, step in enumerate(steps)
                    if step.get("name") == "Pull pinned PostgreSQL 18 strict fixture")
        quick = next(index for index, step in enumerate(steps)
                     if "scripts/agent verify quick" in step.get("run", ""))
        self.assertLess(pull, quick)


if __name__ == "__main__":
    unittest.main()
