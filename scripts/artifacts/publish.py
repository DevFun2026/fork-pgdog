"""Publish already-tested OCI archives; chart publication is a separate last step."""
import json
import io
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
from artifacts.oci import archive_metadata
from artifacts.package_chart import package_chart
from artifacts.registry import assert_tag_absent, manifest_digest
from artifacts.release_receipt import validate_digest, validate_version

IMAGE = "ghcr.io/devfun2026/fork-pgdog"


def command(argv):
    result = subprocess.run(argv, text=True, capture_output=True)
    if result.returncode:
        # Do not print credential-bearing argv or tool stderr from a write job.
        raise ValueError(f"{argv[0]} publication operation failed (exit {result.returncode}); no later artifact is published")
    return result.stdout


def verify_combined(digest, expected_manifests=None):
    validate_digest(digest)
    raw = command(["docker", "buildx", "imagetools", "inspect", IMAGE + "@" + digest, "--raw"])
    index = json.loads(raw)
    platforms = {}
    for descriptor in index.get("manifests", []):
        platform = descriptor.get("platform", {})
        if descriptor.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest":
            continue
        key = (platform.get("os"), platform.get("architecture"))
        if key in platforms:
            raise ValueError("Duplicate runnable platform in combined image")
        platforms[key] = validate_digest(descriptor["digest"])
    if set(platforms) != {("linux", "amd64"), ("linux", "arm64")}:
        raise ValueError("Combined image does not contain both required native platforms")
    if expected_manifests is not None and any(platforms[("linux", arch)] != expected_manifests[arch] for arch in ("amd64", "arm64")):
        raise ValueError("Combined image child digest differs from tested archive")


def publish_images(directory: Path, source_sha: str, image_version: str, chart_version: str):
    validate_version(image_version); validate_version(chart_version)
    metadata = {}
    for arch in ("amd64", "arm64"):
        archive = directory / f"image-{arch}.tar"
        actual = archive_metadata(archive, arch, source_sha)
        recorded = json.loads((directory / f"image-{arch}.json").read_text())
        checks = recorded.pop("checks", None)
        if recorded != actual or checks != {key: "passed" for key in ("chart", "container", "kubernetes", "iac", "container_scan")}:
            raise ValueError("Downloaded archive differs from fully tested native artifact metadata")
        metadata[arch] = actual
    def absent():
        for tag in (image_version, source_sha, image_version + "-amd64", image_version + "-arm64"):
            assert_tag_absent("devfun2026/fork-pgdog", tag)
        assert_tag_absent("devfun2026/charts/fork-pgdog", chart_version)
    absent()
    # Recheck all immutable destination tags immediately before the first write.
    absent()
    for arch in metadata:
        command(["skopeo", "copy", "--all", "--preserve-digests", "oci-archive:" + str(directory / f"image-{arch}.tar"), "docker://" + IMAGE + ":" + image_version + "-" + arch])
        remote = json.loads(command(["docker", "buildx", "imagetools", "inspect", IMAGE + ":" + image_version + "-" + arch, "--format", "{{json .Manifest}}"] ))
        if validate_digest(remote["digest"]) != metadata[arch]["publication_digest"]:
            raise ValueError("Published native image root differs from tested archive")
    command(["docker", "buildx", "imagetools", "create", "--tag", IMAGE + ":" + image_version, "--tag", IMAGE + ":" + source_sha,
             IMAGE + "@" + metadata["amd64"]["publication_digest"], IMAGE + "@" + metadata["arm64"]["publication_digest"]])
    descriptor = json.loads(command(["docker", "buildx", "imagetools", "inspect", IMAGE + ":" + image_version, "--format", "{{json .Manifest}}"] ))
    digest = validate_digest(descriptor["digest"])
    verify_combined(digest, {arch: metadata[arch]["manifest_digest"] for arch in metadata})
    return {"combined": digest, "amd64": metadata["amd64"]["manifest_digest"], "arm64": metadata["arm64"]["manifest_digest"]}


def materialize_chart(root, source_sha, output):
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("Invalid selected chart source SHA")
    result = subprocess.run(["git", "archive", source_sha, "charts/fork-pgdog"], cwd=root, capture_output=True, check=True)
    output.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
        seen = set()
        for member in archive.getmembers():
            if member.name.rstrip("/") in {"charts", "charts/fork-pgdog"} and member.isdir():
                continue
            prefix = "charts/fork-pgdog/"
            if not member.name.startswith(prefix):
                raise ValueError("Chart archive path outside selected source")
            relative = Path(member.name[len(prefix):])
            if relative.is_absolute() or ".." in relative.parts or relative in seen:
                raise ValueError("Unsafe/duplicate chart archive path")
            seen.add(relative)
            target = output / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile() and member.size <= 2_000_000:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
            else:
                raise ValueError("Chart archive requires bounded regular files")
    if not (output / "Chart.yaml").is_file():
        raise ValueError("Selected source contains no chart")


def publish_chart(root, source_sha, image_digest, image_version, chart_version):
    validate_digest(image_digest); validate_version(image_version); validate_version(chart_version)
    verify_combined(image_digest)
    assert_tag_absent("devfun2026/charts/fork-pgdog", chart_version)
    with tempfile.TemporaryDirectory(prefix="fork-pgdog-publish-chart-") as directory:
        source = Path(directory) / "selected-source"
        materialize_chart(root, source_sha, source)
        package = package_chart(source, image_digest, image_version, chart_version, Path(directory))
        command(["helm", "push", str(package), "oci://ghcr.io/devfun2026/charts"])
        # Pull back the published package and inspect its exact pairing.
        pulled = Path(directory) / "pulled"; pulled.mkdir()
        command(["helm", "pull", "oci://ghcr.io/devfun2026/charts/fork-pgdog", "--version", chart_version, "--destination", str(pulled)])
        import hashlib
        if hashlib.sha256(package.read_bytes()).digest() != hashlib.sha256((pulled / package.name).read_bytes()).digest():
            raise ValueError("Published chart bytes differ from the paired local package")
        return {"package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
                "oci_digest": manifest_digest("devfun2026/charts/fork-pgdog", chart_version)}
