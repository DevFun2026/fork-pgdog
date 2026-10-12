from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
import platform
from pathlib import Path, PurePosixPath
import resource
import shlex
import shutil
import stat
import subprocess
import tempfile
from typing import Mapping

from agent_cli.redaction import redact


MAX_PROVIDER_OUTPUT_BYTES = 1_000_000
COMMON_PROVIDER_ENV = frozenset(
    {
        "PATH",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "TZ",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
)
PROXY_ENV = frozenset(
    {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"}
)
PROVIDER_ENV = {
    "claude": frozenset(
        {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"}
    ),
    "codex": frozenset(
        {"OPENAI_API_KEY", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID", "CODEX_API_KEY"}
    ),
    "gemini": frozenset({"GEMINI_API_KEY"}),
}
SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
CATEGORIES = frozenset(
    {
        "architecture",
        "correctness",
        "documentation",
        "maintainability",
        "performance",
        "reliability",
        "security",
        "testing",
    }
)


class ProviderPolicyError(ValueError):
    """Raised when a provider cannot satisfy the independent review policy."""


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _package_bundle(script: Path) -> Path:
    if script.suffix not in {".js", ".mjs", ".cjs"}:
        return script
    for parent in tuple(script.parents)[:4]:
        if (parent / "package.json").is_file():
            home = Path.home().resolve()
            broad_roots = {
                path.resolve()
                for path in (
                    Path("/"),
                    Path("/bin"),
                    Path("/etc"),
                    Path("/lib"),
                    Path("/lib64"),
                    Path("/opt"),
                    Path("/private"),
                    Path("/private/tmp"),
                    Path("/private/var"),
                    Path("/sbin"),
                    Path("/System"),
                    Path("/tmp"),
                    Path("/usr"),
                    Path("/var"),
                    Path("/Library"),
                    Path("/Users"),
                    Path(tempfile.gettempdir()),
                )
            } | {
                home,
                *home.parents,
            }
            resolved_parent = parent.resolve()
            try:
                world_writable = bool(resolved_parent.stat().st_mode & stat.S_IWOTH)
            except OSError:
                world_writable = False
            if resolved_parent in broad_roots or world_writable:
                raise ProviderPolicyError(
                    "provider package bundle resolves to a broad host directory"
                )
            return resolved_parent
    return script


def _prepared_provider_command(
    argv: tuple[str, ...], repository_root: Path, support_paths: tuple[str, ...]
) -> tuple[tuple[str, ...], tuple[Path, ...]]:
    if not argv:
        raise ProviderPolicyError("provider command is empty")
    executable_value = shutil.which(argv[0]) or argv[0]
    executable = Path(executable_value).resolve()
    if not executable.is_file() or _is_inside(executable, repository_root):
        raise ProviderPolicyError(
            "provider executable and support files must be regular files outside the repository"
        )

    interpreter = executable.name.lower()
    interpreter_family = (
        interpreter in {"sh", "bash", "zsh", "dash", "node", "perl", "ruby"}
        or interpreter.startswith("python")
    )
    if interpreter_family and any(
        argument in {"-c", "-e", "--eval", "-m"} for argument in support_paths
    ):
        raise ProviderPolicyError(
            "provider command may not use interpreter inline or module execution"
        )

    path_arguments: list[Path] = []
    for value in support_paths:
        candidate = Path(value)
        if candidate.exists():
            resolved = candidate.resolve()
            if resolved.is_dir():
                raise ProviderPolicyError(
                    "provider command may not grant access to argument directories"
                )
            path_arguments.append(resolved)

    supports: list[Path] = []
    if interpreter_family:
        if len(path_arguments) != 1:
            raise ProviderPolicyError(
                "provider interpreter command requires exactly one external script"
            )
        script = path_arguments[0]
        if _is_inside(script, repository_root):
            raise ProviderPolicyError(
                "provider executable and support files must be outside the repository"
            )
        if script.suffix.lower() not in {".sh", ".py", ".js", ".mjs", ".cjs", ".pl", ".rb"}:
            raise ProviderPolicyError("provider interpreter script type is not approved")
        supports.append(_package_bundle(script))
    elif path_arguments:
        raise ProviderPolicyError(
            "provider binary arguments may not grant access to host files"
        )

    command = (str(executable), *argv[1:])
    try:
        with executable.open("rb") as executable_stream:
            first_line = executable_stream.readline(512).decode(
                "utf-8", errors="ignore"
            )
    except OSError:
        first_line = ""
    if first_line.startswith("#!"):
        shebang = shlex.split(first_line[2:].strip())
        if shebang:
            interpreter_name = shebang[-1] if Path(shebang[0]).name == "env" else shebang[0]
            interpreter_path = shutil.which(interpreter_name)
            if interpreter_path is None:
                raise ProviderPolicyError(
                    f"provider script interpreter is unavailable: {interpreter_name}"
                )
            runtime = Path(interpreter_path).resolve()
            if _is_inside(runtime, repository_root):
                raise ProviderPolicyError("provider interpreter must be outside the repository")
            supports.append(_package_bundle(executable))
            command = (str(runtime), str(executable), *argv[1:])

    unique_supports = tuple(dict.fromkeys(path.resolve() for path in supports))
    return command, unique_supports


def _limit_provider_output() -> None:
    limit = MAX_PROVIDER_OUTPUT_BYTES + 65_536
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))


@dataclass(frozen=True)
class Capability:
    provider: str
    available: bool
    executable: str | None
    version: str | None
    supports_json: bool
    supports_read_only: bool
    reason: str | None


@dataclass(frozen=True)
class ReviewRequest:
    prompt: str
    repository_root: Path
    package_path: Path
    output_schema_path: Path
    timeout: float


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    status: str
    verdict: str | None
    findings_json: str | None
    exit_code: int | None
    stdout_sha256: str | None
    stderr_excerpt: str

    @classmethod
    def timeout(cls, provider: str, stderr: str = "provider timed out") -> "ProviderResult":
        return cls(provider, "incomplete", None, None, None, None, redact(stderr).text[:2000])

    @classmethod
    def invalid(
        cls,
        provider: str,
        raw: str,
        reason: str = "invalid structured output",
    ) -> "ProviderResult":
        digest = sha256(raw.encode("utf-8", errors="replace")).hexdigest()
        return cls(provider, "incomplete", None, None, None, digest, reason[:2000])


def _validate_finding(finding: object) -> None:
    if not isinstance(finding, dict):
        raise ValueError("finding must be an object")
    required = {
        "id",
        "severity",
        "category",
        "file",
        "line",
        "evidence",
        "reasoning",
        "remediation",
        "confidence",
    }
    if set(finding) != required:
        raise ValueError("finding fields do not match schema")
    if not isinstance(finding["id"], str) or not finding["id"]:
        raise ValueError("finding id is required")
    if finding["severity"] not in SEVERITIES:
        raise ValueError("unknown severity")
    if finding["category"] not in CATEGORIES:
        raise ValueError("unknown category")
    file_value = finding["file"]
    if file_value not in (None, ""):
        if not isinstance(file_value, str):
            raise ValueError("finding file must be a string")
        path = PurePosixPath(file_value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("finding file escapes package")
    line = finding["line"]
    if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
        raise ValueError("finding line must be positive")
    for field in ("evidence", "reasoning", "remediation"):
        if not isinstance(finding[field], str) or not finding[field].strip():
            raise ValueError(f"finding {field} is required")
    if finding["confidence"] not in {"low", "medium", "high"}:
        raise ValueError("unknown confidence")


def validated_result(provider: str, payload: object, raw: str) -> ProviderResult:
    if not isinstance(payload, dict) or set(payload) != {"verdict", "findings"}:
        return ProviderResult.invalid(provider, raw)
    verdict = payload.get("verdict")
    findings = payload.get("findings")
    try:
        if verdict not in {"pass", "fail"}:
            raise ValueError("unknown verdict")
        if not isinstance(findings, list):
            raise ValueError("findings must be an array")
        for finding in findings:
            _validate_finding(finding)
        if verdict == "pass" and findings:
            raise ValueError("pass verdict cannot contain findings")
        if verdict == "fail" and not findings:
            raise ValueError("fail verdict requires findings")
    except ValueError as exc:
        return ProviderResult.invalid(provider, raw, str(exc))
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return ProviderResult(
        provider=provider,
        status="completed",
        verdict=verdict,
        findings_json=normalized,
        exit_code=0,
        stdout_sha256=sha256(raw.encode("utf-8")).hexdigest(),
        stderr_excerpt="",
    )


def invoke_provider(
    *,
    provider: str,
    argv: tuple[str, ...],
    request: ReviewRequest,
    parser,
    support_paths: tuple[str, ...] = (),
) -> ProviderResult:
    try:
        sandbox = _sandboxed_command(
            argv,
            request.package_path,
            request.repository_root,
            provider,
            support_paths,
        )
        with sandbox as isolated_argv:
            with tempfile.TemporaryDirectory(prefix="agent-provider-output-") as output_dir:
                stdout_path = Path(output_dir) / "stdout.txt"
                stderr_path = Path(output_dir) / "stderr.txt"
                with stdout_path.open("w", encoding="utf-8") as stdout_stream, stderr_path.open(
                    "w", encoding="utf-8"
                ) as stderr_stream:
                    completed = subprocess.run(
                        isolated_argv,
                        cwd=request.package_path,
                        stdin=subprocess.DEVNULL,
                        text=True,
                        stdout=stdout_stream,
                        stderr=stderr_stream,
                        timeout=request.timeout,
                        check=False,
                        shell=False,
                        env=sandbox.environment,
                        preexec_fn=_limit_provider_output,
                    )
                if stdout_path.stat().st_size > MAX_PROVIDER_OUTPUT_BYTES:
                    return ProviderResult.invalid(
                        provider, "", "provider output exceeds limit"
                    )
                stdout = stdout_path.read_text(encoding="utf-8")
                stderr_raw = stderr_path.read_text(encoding="utf-8")[:MAX_PROVIDER_OUTPUT_BYTES]
    except (subprocess.TimeoutExpired, ProviderPolicyError, OSError) as exc:
        return ProviderResult.timeout(provider, str(exc))
    stderr = redact(stderr_raw, secrets=sandbox.secret_values).text[:2000]
    if completed.returncode != 0:
        return ProviderResult(
            provider,
            "incomplete",
            None,
            None,
            completed.returncode,
            sha256(stdout.encode("utf-8")).hexdigest(),
            stderr or "provider exited non-zero",
        )
    if len(stdout.encode("utf-8")) > MAX_PROVIDER_OUTPUT_BYTES:
        return ProviderResult.invalid(provider, stdout, "provider output exceeds limit")
    result = parser(stdout)
    return ProviderResult(
        result.provider,
        result.status,
        result.verdict,
        result.findings_json,
        completed.returncode,
        result.stdout_sha256,
        stderr or result.stderr_excerpt,
    )


class _sandboxed_command:
    def __init__(
        self,
        argv: tuple[str, ...],
        package_path: Path,
        repository_root: Path,
        provider: str,
        support_paths: tuple[str, ...] = (),
        *,
        allow_network: bool = True,
        include_credentials: bool = True,
    ):
        self.argv = argv
        self.package_path = package_path.resolve()
        self.temporary: tempfile.TemporaryDirectory[str] | None = None
        self.repository_root = repository_root.resolve()
        allowed_environment = COMMON_PROVIDER_ENV
        if not allow_network:
            allowed_environment -= PROXY_ENV
        if include_credentials:
            allowed_environment |= PROVIDER_ENV.get(provider, frozenset())
        self.environment = {
            key: value for key, value in os.environ.items() if key in allowed_environment
        }
        self.secret_values = tuple(
            value
            for key, value in self.environment.items()
            if (
                key in PROVIDER_ENV.get(provider, frozenset()) or key in PROXY_ENV
            )
            and value
        )
        self.output_paths: tuple[Path, Path] | None = None
        self.allow_network = allow_network
        self.argv, self.support_paths = _prepared_provider_command(
            argv,
            self.repository_root,
            support_paths,
        )

    @staticmethod
    def _profile_literal(path: Path) -> str:
        return str(path).replace("\\", "\\\\").replace('"', '\\"')

    def __enter__(self) -> tuple[str, ...]:
        system = platform.system()
        executable = Path(self.argv[0]).resolve()
        command_argv = (str(executable), *self.argv[1:])
        if system == "Darwin":
            sandbox = shutil.which("sandbox-exec")
            if sandbox is None:
                raise ProviderPolicyError("macOS sandbox-exec is required for provider review")
            self.temporary = tempfile.TemporaryDirectory(prefix="agent-provider-sandbox-")
            profile = Path(self.temporary.name) / "review.sb"
            scratch_path = (Path(self.temporary.name) / "scratch").resolve()
            scratch_path.mkdir(mode=0o700)
            self.output_paths = (
                scratch_path / "stdout.txt",
                scratch_path / "stderr.txt",
            )
            package = self._profile_literal(self.package_path)
            executable_path = self._profile_literal(executable)
            scratch = self._profile_literal(scratch_path)
            support_rules = "".join(
                f'(allow file-read* ({"subpath" if path.is_dir() else "literal"} "{self._profile_literal(path)}"))\n'
                for path in self.support_paths
            )
            network_rule = "(allow network*)\n" if self.allow_network else ""
            profile.write_text(
                "(version 1)\n"
                "(deny default)\n"
                "(allow process*)\n"
                f"{network_rule}"
                "(allow sysctl-read)\n"
                "(allow mach-lookup)\n"
                "(allow file-read-metadata)\n"
                "(allow file-read-data "
                "(vnode-type SOCKET TTY CHARACTER-DEVICE DIRECTORY SYMLINK FIFO))\n"
                f'(allow file-read* (subpath "{package}"))\n'
                f'(allow file-read* (literal "{executable_path}"))\n'
                f"{support_rules}"
                f'(allow file-read* (subpath "{scratch}"))\n'
                f'(allow file-write* (subpath "{scratch}"))\n'
                '(allow file-read* (subpath "/System"))\n'
                '(allow file-read* (subpath "/usr"))\n'
                '(allow file-read* (literal "/private/etc/hosts"))\n'
                '(allow file-read* (literal "/private/etc/resolv.conf"))\n'
                '(allow file-read* (literal "/private/var/run/resolv.conf"))\n'
                '(allow file-read* (literal "/private/etc/protocols"))\n'
                '(allow file-read* (literal "/private/etc/services"))\n'
                '(allow file-read* (subpath "/dev"))\n'
                '(allow file-write-data (literal "/dev/null"))\n',
                encoding="utf-8",
            )
            self.environment.update({"HOME": str(scratch_path), "TMPDIR": str(scratch_path)})
            return (sandbox, "-f", str(profile), "--", *command_argv)
        if system == "Linux":
            bubblewrap = shutil.which("bwrap")
            if bubblewrap is None:
                raise ProviderPolicyError("bubblewrap is required for provider review on Linux")
            arguments = [
                bubblewrap,
                "--die-with-parent",
                "--new-session",
                "--unshare-all",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--dir",
                "/agent-support",
                "--dir",
                "/agent-runtime",
                "--dir",
                "/etc",
                "--dir",
                "/etc/ssl",
            ]
            if self.allow_network:
                arguments.insert(arguments.index("--proc"), "--share-net")
            for directory in ("/usr", "/bin", "/lib", "/lib64"):
                path = Path(directory)
                if path.exists():
                    arguments.extend(("--ro-bind", directory, directory))
            for network_path in (
                "/etc/hosts",
                "/etc/resolv.conf",
                "/etc/nsswitch.conf",
                "/etc/gai.conf",
                "/etc/ssl/openssl.cnf",
                "/etc/ssl/certs",
            ):
                if Path(network_path).exists():
                    arguments.extend(("--ro-bind", network_path, network_path))
            if not str(executable).startswith(("/usr/", "/bin/")):
                arguments.extend(
                    ("--ro-bind", str(executable), "/agent-runtime/provider")
                )
                command_argv = ("/agent-runtime/provider", *command_argv[1:])
            support_destinations: dict[Path, Path] = {}
            for index, support_path in enumerate(self.support_paths):
                destination = Path(f"/agent-support/{index}-{support_path.name}")
                arguments.extend(("--ro-bind", str(support_path), str(destination)))
                support_destinations[support_path] = destination
            sandbox_package = Path("/review-package")
            rewritten_argv: list[str] = []
            for index, argument in enumerate(command_argv):
                if index == 0:
                    rewritten_argv.append(argument)
                    continue
                resolved_argument = Path(argument).resolve()
                rewritten_support = None
                for support_path, destination in support_destinations.items():
                    try:
                        relative = resolved_argument.relative_to(support_path)
                    except ValueError:
                        continue
                    rewritten_support = destination / relative
                    break
                if rewritten_support is not None:
                    rewritten_argv.append(str(rewritten_support))
                    continue
                try:
                    package_relative = resolved_argument.relative_to(self.package_path)
                except ValueError:
                    rewritten_argv.append(argument)
                else:
                    rewritten_argv.append(str(sandbox_package / package_relative))
            command_argv = tuple(rewritten_argv)
            arguments.extend(
                (
                    "--ro-bind",
                    str(self.package_path),
                    str(sandbox_package),
                    "--chdir",
                    str(sandbox_package),
                    "--",
                    *command_argv,
                )
            )
            self.environment.update({"HOME": "/tmp", "TMPDIR": "/tmp"})
            return tuple(arguments)
        raise ProviderPolicyError(f"no supported provider sandbox for {system}")

    def __exit__(self, exc_type, exc, traceback) -> bool:
        if self.temporary is not None:
            self.temporary.cleanup()
        return False


def select_reviewer(
    *,
    author: str,
    order: tuple[str, ...],
    capabilities: Mapping[str, Capability] | None = None,
) -> str:
    independent = tuple(provider for provider in order if provider != author)
    if not independent:
        raise ProviderPolicyError("no independent reviewer is configured")
    if capabilities is None:
        return independent[0]
    for provider in independent:
        capability = capabilities.get(provider)
        if (
            capability is not None
            and capability.available
            and capability.supports_json
            and capability.supports_read_only
        ):
            return provider
    raise ProviderPolicyError("no available independent reviewer satisfies capabilities")


def probe_capability(
    *,
    provider: str,
    executable: str | None,
    help_arguments: tuple[str, ...],
    json_markers: tuple[str, ...],
    read_only_markers: tuple[str, ...],
    prefix_arguments: tuple[str, ...] = (),
    repository_root: Path | None = None,
) -> Capability:
    if executable is None:
        return Capability(
            provider, False, None, None, False, False, f"{provider} executable not found"
        )
    root = (repository_root or Path.cwd()).resolve()

    def run_probe(arguments: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="agent-capability-package-") as package_dir:
            package = Path(package_dir)
            sandbox = _sandboxed_command(
                (executable, *prefix_arguments, *arguments),
                package,
                root,
                provider,
                prefix_arguments,
                allow_network=False,
                include_credentials=False,
            )
            with sandbox as isolated_argv, tempfile.TemporaryDirectory(
                prefix="agent-capability-output-"
            ) as output_dir:
                stdout_path = Path(output_dir) / "stdout.txt"
                stderr_path = Path(output_dir) / "stderr.txt"
                with stdout_path.open("w", encoding="utf-8") as stdout_stream, stderr_path.open(
                    "w", encoding="utf-8"
                ) as stderr_stream:
                    completed = subprocess.run(
                        isolated_argv,
                        cwd=package,
                        stdin=subprocess.DEVNULL,
                        text=True,
                        stdout=stdout_stream,
                        stderr=stderr_stream,
                        timeout=10,
                        check=False,
                        shell=False,
                        env=sandbox.environment,
                        preexec_fn=_limit_provider_output,
                    )
                stdout = stdout_path.read_text(encoding="utf-8")[:MAX_PROVIDER_OUTPUT_BYTES]
                stderr = stderr_path.read_text(encoding="utf-8")[:MAX_PROVIDER_OUTPUT_BYTES]
                return subprocess.CompletedProcess(
                    completed.args, completed.returncode, stdout, stderr
                )

    try:
        version_result = run_probe(("--version",))
        help_result = run_probe(help_arguments)
    except (OSError, ProviderPolicyError, subprocess.TimeoutExpired) as exc:
        return Capability(provider, False, executable, None, False, False, str(exc))
    version = (version_result.stdout or version_result.stderr).strip().splitlines()
    version_text = version[0][:200] if version else None
    help_text = f"{help_result.stdout}\n{help_result.stderr}"
    supports_json = all(marker in help_text for marker in json_markers)
    supports_read_only = all(marker in help_text for marker in read_only_markers)
    available = (
        version_result.returncode == 0
        and help_result.returncode == 0
        and supports_json
        and supports_read_only
    )
    reason = None
    if not available:
        missing = []
        if not supports_json:
            missing.append("structured output")
        if not supports_read_only:
            missing.append("read-only mode")
        if version_result.returncode != 0 or help_result.returncode != 0:
            missing.append("successful capability probe")
        reason = "missing " + ", ".join(missing)
    return Capability(
        provider,
        available,
        executable,
        version_text,
        supports_json,
        supports_read_only,
        reason,
    )
