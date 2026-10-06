"""Validate rendered Kubernetes objects and operator-supplied inline TOML."""
import math
import tomllib


def validate_rendered_chart(documents: list[dict], values: dict) -> None:
    docs = [d for d in documents if d]
    if any(d.get("kind") == "Secret" for d in docs):
        raise ValueError("Chart must reference existing Secrets, never render a Secret")
    by_kind = {}
    for doc in docs:
        by_kind.setdefault(doc.get("kind"), []).append(doc)
    for kind in ("Deployment", "Service", "ServiceAccount"):
        if len(by_kind.get(kind, [])) != 1:
            raise ValueError(f"Expected exactly one {kind}")
    deployment = by_kind["Deployment"][0]
    pod = deployment["spec"]["template"]["spec"]
    if pod.get("automountServiceAccountToken") is not False:
        raise ValueError("ServiceAccount token must be disabled")
    if by_kind["ServiceAccount"][0].get("automountServiceAccountToken") is not False:
        raise ValueError("ServiceAccount token must be disabled")
    if pod.get("nodeSelector", {}).get("kubernetes.io/os") != "linux":
        raise ValueError("Pod must select Linux nodes")
    main, init = pod["containers"], pod["initContainers"]
    if len(main) != 1 or len(init) != 1:
        raise ValueError("Expected PgDog and one configcheck initContainer")
    main, init = main[0], init[0]
    if main["image"] != init["image"]:
        raise ValueError("configcheck and PgDog must use the same image")
    policy = values.get("queryPolicy", "unrestricted")
    read_policy = values.get("readPolicy", {}).get("existingConfigMap", "")
    if policy not in ("unrestricted", "strict-read"):
        raise ValueError("queryPolicy must be unrestricted or strict-read")
    if policy == "strict-read" and not read_policy:
        raise ValueError("queryPolicy strict-read requires readPolicy.existingConfigMap")
    if policy == "unrestricted" and read_policy:
        raise ValueError("readPolicy.existingConfigMap requires queryPolicy strict-read")
    policy_args = ["--query-policy", "strict-read", "--read-policy-file",
                   "/etc/pgdog/read-policy/read-policy.toml"]
    containers = (main, init)
    raw_volumes = pod.get("volumes", [])
    volumes = {volume.get("name"): volume for volume in raw_volumes}
    if policy == "strict-read":
        for container in containers:
            args = container.get("args", [])
            if (args.count("--query-policy") != 1 or args.count("strict-read") != 1
                    or args.count("--read-policy-file") != 1
                    or args.count("/etc/pgdog/read-policy/read-policy.toml") != 1
                    or not all(arg in args for arg in policy_args)):
                raise ValueError("Both containers must receive the strict-read query-policy arguments")
            if args.index("--query-policy") + 1 != args.index("strict-read"):
                raise ValueError("query-policy arguments must be paired")
            if args.index("--read-policy-file") + 1 != args.index("/etc/pgdog/read-policy/read-policy.toml"):
                raise ValueError("read-policy-file argument must name the mounted policy")
            mounts = [mount for mount in container.get("volumeMounts", []) if mount.get("name") == "read-policy"]
            if len(mounts) != 1 or mounts[0].get("mountPath") != "/etc/pgdog/read-policy/read-policy.toml" or mounts[0].get("subPath") != "read-policy.toml" or mounts[0].get("readOnly") is not True:
                raise ValueError("Both containers require the read-only read-policy.toml mount")
        volume = volumes.get("read-policy", {})
        config_map = volume.get("configMap", {})
        if (sum(volume.get("name") == "read-policy" for volume in raw_volumes) != 1
                or config_map.get("name") != read_policy
                or config_map.get("items") != [{"key": "read-policy.toml", "path": "read-policy.toml"}]):
            raise ValueError("read-policy volume must mount read-policy.toml from readPolicy.existingConfigMap")
    else:
        if "read-policy" in volumes:
            raise ValueError("Unrestricted policy must not mount read-policy")
        for container in containers:
            args = container.get("args", [])
            if any(arg in args for arg in policy_args):
                raise ValueError("Unrestricted policy must not receive strict-read arguments")
            if any(mount.get("name") == "read-policy" for mount in container.get("volumeMounts", [])):
                raise ValueError("Unrestricted policy must not mount read-policy")
    if init.get("args", [])[-1:] != ["configcheck"]:
        raise ValueError("initContainer must run configcheck")
    for container in (main, init):
        security = container.get("securityContext", {})
        if security.get("runAsNonRoot") is not True or security.get("runAsUser") != 10001 or security.get("runAsGroup") != 10001:
            raise ValueError("Both containers must enforce non-root UID/GID 10001")
        if (security.get("readOnlyRootFilesystem") is not True
                or security.get("allowPrivilegeEscalation") is not False
                or security.get("capabilities") != {"drop": ["ALL"]}
                or security.get("seccompProfile") != {"type": "RuntimeDefault"}):
            raise ValueError("Container hardening contract violated")
        for mount in container.get("volumeMounts", []):
            if mount["name"] != "tmp" and mount.get("readOnly") is not True:
                raise ValueError("Configuration and Secret mounts must be read-only")
    if main.get("startupProbe", {}).get("tcpSocket") != {"port": "pgsql"} or main.get("livenessProbe", {}).get("tcpSocket") != {"port": "pgsql"}:
        raise ValueError("Startup/liveness must use the PgDog listener")
    if main.get("readinessProbe", {}).get("httpGet") != {"path": "/", "port": "health"}:
        raise ValueError("Readiness must use the backend-aware health endpoint")
    service = by_kind["Service"][0]["spec"]
    if len(service["ports"]) != 1 or service["ports"][0].get("targetPort") != "pgsql":
        raise ValueError("Service may expose only PostgreSQL")
    selectors = deployment["spec"]["selector"]["matchLabels"]
    if service["selector"] != selectors or any(deployment["spec"]["template"]["metadata"]["labels"].get(k) != v for k, v in selectors.items()):
        raise ValueError("Deployment and Service selectors differ")
    inline = values["config"]["pgdogToml"]
    if inline:
        try:
            config = tomllib.loads(inline)
        except tomllib.TOMLDecodeError:
            # TOML parser diagnostics can contain secrets from the offending line.
            raise ValueError("Invalid inline TOML; validate it locally") from None
        def reject_credentials(item):
            if isinstance(item, dict):
                for key, value in item.items():
                    if key == "tls_private_key" and isinstance(value, str) and value.startswith("/etc/pgdog/tls/") and ".." not in value.split("/") and values["tls"]["existingSecret"]:
                        continue
                    if any(part in key.lower() for part in ("password", "token", "secret", "private_key")):
                        raise ValueError("Credential-bearing TOML must use config.existingSecret")
                    reject_credentials(value)
            elif isinstance(item, list):
                for value in item:
                    reject_credentials(value)
        reject_credentials(config)
        general = config.get("general", {})
        if general.get("host", "0.0.0.0") != "0.0.0.0":
            raise ValueError("Inline general.host must bind 0.0.0.0")
        for key, field, default in (("port", "containerPort", 6432), ("healthcheck_port", "healthcheckPort", None)):
            if general.get(key, default) != values[field]:
                raise ValueError(f"Inline general.{key} must match {field}")
        shutdown = general.get("shutdown_timeout", 60000)
        if "shutdown_termination_timeout" not in general:
            raise ValueError("Set a finite general.shutdown_termination_timeout to fit the Pod grace")
        wait = general["shutdown_termination_timeout"]
        if not all(isinstance(n, int) and not isinstance(n, bool) and n >= 0 for n in (shutdown, wait)):
            raise ValueError("Shutdown timeouts must be nonnegative milliseconds")
        if values["terminationGracePeriodSeconds"] <= math.ceil((shutdown + wait) / 1000):
            raise ValueError("Pod grace must exceed both PgDog shutdown timeouts")
        maps = by_kind.get("ConfigMap", [])
        if len(maps) != 1 or maps[0].get("data", {}).get("pgdog.toml") != inline:
            raise ValueError("Rendered inline TOML differs from operator input")
