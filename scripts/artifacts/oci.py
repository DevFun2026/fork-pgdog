"""Read verified OCI blobs without extracting archive paths to the filesystem."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile


def archive_metadata(path: Path, arch: str, source_sha: str):
    if arch not in {"amd64", "arm64"} or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("Invalid native architecture/source SHA")
    images = []
    with tarfile.open(path, "r:*") as archive:
        names = [member.name for member in archive.getmembers()]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate archive entries")
        def read(name, maximum=16_000_000):
            member = archive.getmember(name)
            if not member.isfile() or member.size > maximum:
                raise ValueError("Invalid OCI metadata member")
            return archive.extractfile(member).read()
        def blob(descriptor):
            digest = descriptor["digest"]
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                raise ValueError("Unsupported OCI digest")
            data = read("blobs/sha256/" + digest[7:])
            if hashlib.sha256(data).hexdigest() != digest[7:] or len(data) != descriptor["size"]:
                raise ValueError("OCI blob digest/size mismatch")
            return json.loads(data)
        def walk(descriptor, depth=0):
            if depth > 4:
                raise ValueError("OCI index nesting exceeds bound")
            value = blob(descriptor)
            if "manifests" in value:
                for child in value["manifests"]:
                    walk(child, depth + 1)
            elif descriptor.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest":
                # BuildKit provenance is transported with the index; it is not a runnable platform.
                return
            elif "config" in value:
                config = blob(value["config"])
                if config.get("os") != "linux" or config.get("architecture") not in {"amd64", "arm64"}:
                    raise ValueError("Unknown runnable platform in OCI archive")
                images.append((descriptor, value, config))
            else:
                raise ValueError("Unsupported OCI manifest")
        index_data = read("index.json")
        index = json.loads(index_data)
        if len(index["manifests"]) != 1:
            raise ValueError("OCI archive must have exactly one publication root")
        publication_digest = index["manifests"][0]["digest"]
        for descriptor in index["manifests"]:
            walk(descriptor)
        if len(images) != 1 or images[0][2]["architecture"] != arch:
            raise ValueError("Native OCI archive must contain exactly the selected runnable platform")
        descriptor, manifest, config = images[0]
        if config.get("config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != source_sha:
            raise ValueError("OCI image source label differs from approved SHA")
    with path.open("rb") as stream:
        archive_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"source_sha": source_sha, "platform": "linux/" + arch, "archive_sha256": archive_hash,
            "manifest_digest": descriptor["digest"], "publication_digest": publication_digest, "config_digest": manifest["config"]["digest"]}


def import_image(path, arch, source_sha, metadata_output):
    metadata = archive_metadata(path, arch, source_sha)
    subprocess.run(["skopeo", "copy", "--override-os", "linux", "--override-arch", arch, "oci-archive:" + str(path), "docker-daemon:fork-pgdog:local"], check=True)
    loaded = subprocess.run(["docker", "image", "inspect", "fork-pgdog:local", "--format", "{{.Id}}"], check=True, capture_output=True, text=True).stdout.strip()
    if loaded != metadata["config_digest"]:
        raise ValueError("Imported image differs from the archive tested for publication")
    metadata_output.write_text(json.dumps(metadata, sort_keys=True) + "\n")
