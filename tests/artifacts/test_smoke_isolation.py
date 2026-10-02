import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class SmokeIsolationTests(unittest.TestCase):
    def test_failure_cleanup_and_kubernetes_commands_are_isolated(self):
        script = ROOT / "scripts/helm-smoke.sh"
        self.assertTrue(script.is_file(), "Kind smoke harness missing")
        for fail in ("kind", "kubectl"):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                log = path / "calls.jsonl"
                for tool in ("kind", "kubectl", "helm"):
                    binary = path / tool
                    binary.write_text("#!/usr/bin/env python3\nimport json,os,sys\nwith open(os.environ['CALL_LOG'],'a') as f: f.write(json.dumps([os.path.basename(sys.argv[0]),*sys.argv[1:]])+'\\n')\nif os.path.basename(sys.argv[0])==os.environ['FAIL_TOOL'] and ('create' in sys.argv or 'apply' in sys.argv): sys.exit(1)\n")
                    binary.chmod(0o755)
                current = path / "existing-kubeconfig"
                current.write_text("DO NOT TOUCH\n")
                env = dict(os.environ, PATH=str(path) + os.pathsep + os.environ["PATH"], KUBECONFIG=str(current), CALL_LOG=str(log), FAIL_TOOL=fail)
                isolated_script = path / "repo/scripts/helm-smoke.sh"
                isolated_script.parent.mkdir(parents=True)
                isolated_script.write_bytes(script.read_bytes())
                result = subprocess.run(["bash", str(isolated_script), "--image", "fixture:local"], env=env, text=True, capture_output=True, timeout=20, cwd=path)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(current.read_text(), "DO NOT TOUCH\n")
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                created = next(c for c in calls if c[:3] == ["kind", "create", "cluster"])
                name = created[created.index("--name") + 1]
                self.assertTrue(name.startswith("fork-pgdog-smoke-"))
                self.assertIn(["kind", "delete", "cluster", "--name", name], calls)
                for call in calls:
                    if call[0] == "kubectl":
                        self.assertIn("--kubeconfig", call)
                        self.assertNotEqual(call[call.index("--kubeconfig") + 1], str(current))
                        self.assertEqual(call[call.index("--context") + 1], "kind-" + name)
                        self.assertIn("--namespace", call)


if __name__ == "__main__":
    unittest.main()
