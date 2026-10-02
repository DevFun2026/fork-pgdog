"""Scan only bounded, source-bound artifact inputs with pinned Trivy."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def command(argv, root=None):
    result = subprocess.run(argv, cwd=root, text=True, capture_output=True)
    if result.returncode:
        raise ValueError(f"{argv[0]} operation failed (exit {result.returncode}); inspect local scanner diagnostics")
    return result.stdout


def valid_image(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9./:_@-]*", value):
        raise ValueError("Invalid image reference")
    return value


def source_identity(root):
    sha = command(["git", "rev-parse", "HEAD"], root).strip()
    files = command(["git", "ls-files", "-c", "-o", "--exclude-standard", "-z"], root).split("\0")
    digest = hashlib.sha256()
    for name in sorted(set(files) - {""}):
        path = root / name
        if path.is_symlink():
            digest.update(name.encode() + b"\0symlink\0" + os.fsencode(os.readlink(path)))
            continue
        if not path.exists():
            digest.update(name.encode() + b"\0deleted\0")
            continue
        digest.update(name.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    return sha, digest.hexdigest()


def image_identity(image):
    return command(["docker", "image", "inspect", valid_image(image), "--format", "{{.Id}}"] ).strip()


def input_hashes(root):
    directory = root / ".agent/.runs/artifacts/scan-input"
    files = [p for p in sorted(directory.rglob("*")) if p.is_file()]
    if not files or any(p.is_symlink() for p in files):
        raise ValueError("Missing or unsafe bounded scan input")
    return {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def prepare_scan(root: Path, image: str):
    valid_image(image)
    directory = root / ".agent/.runs/artifacts/scan-input"
    directory.mkdir(parents=True, exist_ok=True)
    # Refuse unexpected files rather than recursively deleting a caller-controlled directory.
    if any(p.name not in {"Dockerfile", "chart.yaml"} for p in directory.iterdir()):
        raise ValueError("Unexpected files in bounded scan directory")
    shutil.copyfile(root / "applications/pgdog/Dockerfile", directory / "Dockerfile")
    rendered = command(["helm", "template", "artifact-scan", str(root / "charts/fork-pgdog"), "--values", str(root / "charts/fork-pgdog/examples/values.yaml")])
    (directory / "chart.yaml").write_text(rendered)
    source, tree = source_identity(root)
    binding = {"source_sha": source, "tree_sha256": tree, "image": image, "image_config_digest": image_identity(image), "inputs": input_hashes(root)}
    (root / ".agent/.runs/artifacts/scan-binding.json").write_text(json.dumps(binding, sort_keys=True) + "\n")
    return binding


def load_binding(root):
    return json.loads((root / ".agent/.runs/artifacts/scan-binding.json").read_text())


def validate_binding(root, binding):
    if set(binding) != {"source_sha", "tree_sha256", "image", "image_config_digest", "inputs"}:
        raise ValueError("Invalid scan binding")
    source, tree = source_identity(root)
    if binding["source_sha"] != source or binding["tree_sha256"] != tree or binding["inputs"] != input_hashes(root) or binding["image_config_digest"] != image_identity(binding["image"]):
        raise ValueError("Scan binding is stale or image/config inputs changed")


def require_version():
    if not re.search(r"^Version: 0\.74\.0$", command(["trivy", "--version"]), re.MULTILINE):
        raise ValueError("Artifact scanner requires Trivy 0.74.0")


def run_scan(root, scanner):
    require_version()
    binding = load_binding(root)
    validate_binding(root, binding)
    common = ["--severity", "HIGH,CRITICAL", "--exit-code", "1", "--format", "json"]
    if scanner == "container":
        command(["trivy", "image", "--download-db-only"], root)
        argv = ["trivy", "image", "--skip-db-update", "--scanners", "vuln", "--image-src", "docker", *common, binding["image"]]
    elif scanner == "iac":
        argv = ["trivy", "config", *common, str(root / ".agent/.runs/artifacts/scan-input")]
    else:
        raise ValueError("Expected iac or container scanner")
    result = subprocess.run(argv, cwd=root, text=True, capture_output=True)
    # Preserve sanitized scanner output locally; no implicit upload.
    path = root / f".agent/.runs/artifacts/{scanner}-scan.json"
    path.write_text(result.stdout)
    if result.returncode:
        raise ValueError(f"{scanner} scan failed (exit {result.returncode}); inspect {path.name}")
    report = json.loads(result.stdout)
    if not isinstance(report, dict) or not isinstance(report.get("Results"), list) or not report["Results"]:
        raise ValueError("Malformed or missing scanner coverage")
    validate_binding(root, binding)
    print(json.dumps({"scanner": scanner, "status": "passed", "source_sha": binding["source_sha"], "tree_sha256": binding["tree_sha256"], "image_config_digest": binding["image_config_digest"]}, sort_keys=True))
