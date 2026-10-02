"""Fail-closed GHCR tag preflight. This module has no write operation."""
import base64
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request


def assert_absent_response(status, body, *, authenticated):
    errors = body.get("errors", []) if isinstance(body, dict) else []
    if not authenticated or status != 404 or not errors or any(error.get("code") != "MANIFEST_UNKNOWN" for error in errors):
        raise ValueError(f"Registry did not confirm authenticated manifest absence (HTTP {status}); refusing publish")


def manifest_request(name, tag):
    if not re.fullmatch(r"devfun2026/(?:fork-pgdog|charts/fork-pgdog)", name) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag):
        raise ValueError("Invalid owned registry name/tag")
    token = os.environ.get("GITHUB_TOKEN")
    actor = os.environ.get("GITHUB_ACTOR")
    if not token or not actor:
        raise ValueError("Authenticated read-only GHCR credentials are required for tag preflight")
    basic = base64.b64encode(f"{actor}:{token}".encode()).decode()
    query = urllib.parse.urlencode({"service": "ghcr.io", "scope": f"repository:{name}:pull"})
    request = urllib.request.Request("https://ghcr.io/token?" + query, headers={"Authorization": "Basic " + basic})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            bearer = json.load(response)["token"]
        request = urllib.request.Request(f"https://ghcr.io/v2/{name}/manifests/{tag}", headers={"Authorization": "Bearer " + bearer, "Accept": "application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.list.v2+json"})
        return request
    except (urllib.error.URLError, KeyError, OSError):
        raise ValueError("Registry authentication/network preflight failed; refusing publish") from None


def assert_tag_absent(name, tag):
    request = manifest_request(name, tag)
    try:
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raise ValueError("Registry tag already exists; refusing overwrite")
        except urllib.error.HTTPError as error:
            try:
                body = json.loads(error.read(32768))
            except json.JSONDecodeError:
                body = {}
            assert_absent_response(error.code, body, authenticated=True)
    except (urllib.error.URLError, KeyError, OSError):
        raise ValueError("Registry authentication/network preflight failed; refusing publish") from None


def manifest_digest(name, tag):
    """Hash raw OCI bytes, including Helm manifests whose config is not an image."""
    import hashlib
    request = manifest_request(name, tag)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(2_000_001)
            if response.status != 200 or len(raw) > 2_000_000:
                raise ValueError("Registry manifest response is invalid or exceeds bound")
            body = json.loads(raw)
            if not isinstance(body, dict) or body.get("schemaVersion") != 2:
                raise ValueError("Registry manifest schema is invalid")
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            advertised = response.headers.get("Docker-Content-Digest")
            if advertised is not None and advertised != digest:
                raise ValueError("Registry manifest digest does not match response bytes")
            return digest
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        raise ValueError("Registry manifest verification failed") from None
