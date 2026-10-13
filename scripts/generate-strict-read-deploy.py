#!/usr/bin/env python3
"""Generate paired strict-read/write Helm values from explicit operator inputs."""
import argparse
import json
import pathlib
import re
import sys

PLACEHOLDER = re.compile(r"<|>|REPLACE_ME|CHANGEME", re.I)
DNS = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
IDENT = re.compile(r"^[a-z_][a-z0-9_$]*$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
REQUIRED = {
    "namespace", "kube_context", "postgres_major_version", "database_name", "database_alias",
    "protected_relations", "schema_revision", "image_repository", "image_digest", "users_secret",
    "client_tls_secret", "backend_ca_filename", "read_policy_configmap"
}


def fail(message):
    raise ValueError(message)


def require_text(data, key):
    value = data.get(key)
    if not isinstance(value, str) or not value.strip() or PLACEHOLDER.search(value):
        fail(f"{key} must be a real, non-placeholder string")
    return value.strip()


def validate(data):
    if not isinstance(data, dict): fail("input must be a JSON object")
    missing = sorted(REQUIRED - data.keys())
    extra = sorted(data.keys() - REQUIRED - {"backend_host", "backend_port", "image_pull_secret", "backend_mtls"})
    if missing: fail("missing required inputs: " + ", ".join(missing))
    if extra: fail("unsupported input keys: " + ", ".join(extra))
    for key in REQUIRED - {"protected_relations", "postgres_major_version"}:
        require_text(data, key)
    major = data["postgres_major_version"]
    if isinstance(major, bool) or not isinstance(major, int) or major not in (12, 18):
        fail("postgres_major_version must be integer 12 or 18")
    if not DNS.fullmatch(data["namespace"]): fail("namespace must be a Kubernetes DNS name")
    if not data["kube_context"] or PLACEHOLDER.search(data["kube_context"]): fail("kube_context must be explicit")
    if not DIGEST.fullmatch(data["image_digest"]): fail("image_digest must be immutable sha256:<64 lowercase hex>")
    if not re.fullmatch(r"[a-z0-9]+([._-]+[a-z0-9]+)*(?:/[a-z0-9]+([._-]+[a-z0-9]+)*)*", data["image_repository"]):
        fail("image_repository must be lowercase OCI repository path")
    if not IDENT.fullmatch(data["database_alias"]): fail("database_alias must be a simple PgDog identifier")
    if not data["database_name"] or PLACEHOLDER.search(data["database_name"]): fail("database_name must be real")
    rels = data["protected_relations"]
    if not isinstance(rels, list) or not rels: fail("protected_relations must be a nonempty list")
    for rel in rels:
        if not isinstance(rel, str) or len(rel.split(".")) != 2 or not all(IDENT.fullmatch(x) for x in rel.split(".")):
            fail("each protected relation must be a schema-qualified ordinary-table name (schema.table)")
    if len(set(rels)) != len(rels): fail("protected_relations must be unique")
    port = data.get("backend_port", 5432)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535: fail("backend_port must be an integer port")
    host = data.get("backend_host", "staging-postgres.database.svc.cluster.local")
    if not host or PLACEHOLDER.search(host): fail("backend_host must be explicit")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host): fail("backend_host must be a DNS hostname")
    for key in ("users_secret", "client_tls_secret", "read_policy_configmap"):
        if not DNS.fullmatch(data[key]): fail(f"{key} must be a Kubernetes DNS name")
    ca = data["backend_ca_filename"]
    if not re.fullmatch(r"[A-Za-z0-9._-]+", ca) or ca in (".", ".."): fail("backend_ca_filename must be a safe mounted filename")
    pull = data.get("image_pull_secret")
    if pull is not None and not DNS.fullmatch(pull): fail("image_pull_secret must be a Kubernetes DNS name")
    if data.get("backend_mtls", False) is not False:
        fail("backend_mtls is not generated; use a separately reviewed TLS design if required")
    return host, port


def toml_string(s):
    return json.dumps(s, ensure_ascii=False)


def render(data, host, port, policy):
    repo, digest = data["image_repository"], data["image_digest"]
    cert = "/etc/pgdog/tls/tls.crt"
    key = "/etc/pgdog/tls/tls.key"
    ca = "/etc/pgdog/tls/" + data["backend_ca_filename"]
    lines = [
        "[general]", 'host = "0.0.0.0"', "port = 6432", "healthcheck_port = 9090",
        "shutdown_timeout = 120000", "shutdown_termination_timeout = 10000",
        'passthrough_auth = "enabled"', "tls_client_required = true",
        f"tls_certificate = {toml_string(cert)}", f"tls_private_key = {toml_string(key)}",
        'tls_verify = "verify_full"', f"tls_server_ca_certificate = {toml_string(ca)}", "",
        "[[databases]]", f"name = {toml_string(data['database_alias'])}",
        f"database_name = {toml_string(data['database_name'])}", f"host = {toml_string(host)}",
        f"port = {port}", 'role = "primary"', ""
    ]
    values = {
        "image": {"repository": repo, "tag": "", "digest": digest, "pullPolicy": "IfNotPresent"},
        "imagePullSecrets": ([{"name": data["image_pull_secret"]}] if data.get("image_pull_secret") else []),
        "queryPolicy": policy,
        "users": {"existingSecret": data["users_secret"]},
        "tls": {"existingSecret": data["client_tls_secret"]},
        "config": {"pgdogToml": "\n".join(lines), "existingConfigMap": "", "existingSecret": ""},
    }
    if policy == "strict-read": values["readPolicy"] = {"existingConfigMap": data["read_policy_configmap"]}
    return values


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, type=pathlib.Path)
    ap.add_argument("--output", required=True, type=pathlib.Path)
    args = ap.parse_args()
    try:
        data = json.loads(args.input.read_text())
        host, port = validate(data)
        if args.output.exists() and any(args.output.iterdir()): fail("output directory must be empty")
        args.output.mkdir(parents=True, exist_ok=True)
        try:
            import yaml
        except ImportError:
            fail("PyYAML is required to emit Helm values")
        for name, policy in (("read-values.yaml", "strict-read"), ("write-values.yaml", "unrestricted")):
            (args.output / name).write_text(yaml.safe_dump(render(data, host, port, policy), sort_keys=False))
        manifest = [
            f"schema_revision = {toml_string(data['schema_revision'])}", "",
            "[[databases]]", f"name = {toml_string(data['database_alias'])}",
            "relations = [" + ", ".join(toml_string(r) for r in data["protected_relations"]) + "]",
        ]
        (args.output / "read-policy.toml").write_text("\n".join(manifest).rstrip() + "\n")
        print(f"Generated paired values and read-policy manifest under {args.output}")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0

if __name__ == "__main__": raise SystemExit(main())
