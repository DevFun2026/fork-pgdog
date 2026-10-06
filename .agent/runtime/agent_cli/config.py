from __future__ import annotations

import json
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

import tomllib

SUPPORTED_PROVIDERS = frozenset({"claude", "gemini", "codex"})
SUPPORTED_SECURITY_PROFILES = frozenset({"baseline", "standard", "high"})
SUPPORTED_SCANNERS = frozenset({"dependency", "license", "sast", "iac", "container"})


class ConfigError(ValueError):
    """Raised when project configuration violates the runtime contract."""


@dataclass(frozen=True)
class ReviewConfig:
    enabled: bool
    require_independent_provider: bool
    max_package_bytes: int
    provider_order: tuple[str, ...]
    provider_commands: Mapping[str, tuple[str, ...]]
    max_estimated_tokens: int = 64000
    partition_enabled: bool = False
    max_aggregate_bytes: int = 2500000
    max_aggregate_tokens: int = 800000
    partition_target_bytes: int = 250000


@dataclass(frozen=True)
class MemoryConfig:
    enabled: bool
    startup_char_budget: int
    local_retention_days: int
    startup_estimated_token_budget: int = 1200


@dataclass(frozen=True)
class SecurityConfig:
    required_scanners: tuple[str, ...]
    scanner_commands: Mapping[str, tuple[str, ...]]
    scanner_version_commands: Mapping[str, tuple[str, ...]]
    scanner_support_paths: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True)
class ProjectConfig:
    name: str
    security_profile: str
    commands: Mapping[str, tuple[str, ...]]
    review: ReviewConfig
    memory: MemoryConfig
    security: SecurityConfig


def _table(data: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a table")
    return value


def _positive_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConfigError(f"{field} must be a positive integer")
    return value


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{field} must be a boolean")
    return value


def _load_commands(table: Mapping[str, Any]) -> Mapping[str, tuple[str, ...]]:
    commands: dict[str, tuple[str, ...]] = {}
    for command_id, value in table.items():
        if not isinstance(command_id, str) or not command_id:
            raise ConfigError("command IDs must be non-empty strings")
        if not isinstance(value, list):
            raise ConfigError(f"commands.{command_id} must be an array")
        if any(not isinstance(item, str) or not item for item in value):
            raise ConfigError(
                f"commands.{command_id} must contain non-empty string arguments"
            )
        commands[command_id] = tuple(value)
    return MappingProxyType(commands)


def load_config(path: str | Path) -> ProjectConfig:
    config_path = Path(path)
    try:
        with config_path.open("rb") as stream:
            data = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot load config: {exc}") from exc

    allowed_top_level = {
        "project",
        "commands",
        "review",
        "documentation",
        "memory",
        "security",
    }
    unknown = sorted(set(data) - allowed_top_level)
    if unknown:
        raise ConfigError(f"unknown top-level configuration: {', '.join(unknown)}")

    project = _table(data, "project")
    name = project.get("name", "agent-project-template")
    if not isinstance(name, str) or not name.strip():
        raise ConfigError("project.name must be a non-empty string")
    security_profile = project.get("security_profile", "standard")
    if security_profile not in SUPPORTED_SECURITY_PROFILES:
        raise ConfigError(f"unsupported security profile: {security_profile}")

    review = _table(data, "review")
    order_value = review.get("provider_order", ["claude", "codex", "gemini"])
    if not isinstance(order_value, list) or any(
        not isinstance(item, str) for item in order_value
    ):
        raise ConfigError("review.provider_order must be an array of strings")
    provider_order = tuple(order_value)
    if len(set(provider_order)) != len(provider_order):
        raise ConfigError("duplicate provider in review.provider_order")
    unsupported = [item for item in provider_order if item not in SUPPORTED_PROVIDERS]
    if unsupported:
        raise ConfigError(f"unsupported provider: {unsupported[0]}")
    provider_commands_table = _table(review, "provider_commands")
    provider_commands: dict[str, tuple[str, ...]] = {}
    for provider in SUPPORTED_PROVIDERS:
        value = provider_commands_table.get(provider, ["agy" if provider == "gemini" else provider])
        if not isinstance(value, list):
            raise ConfigError(
                f"review.provider_commands.{provider} must be an argument array"
            )
        command = tuple(value)
        if not command or any(not isinstance(item, str) or not item for item in command):
            raise ConfigError(f"review.provider_commands.{provider} must be an argument array")
        provider_commands[provider] = command

    memory = _table(data, "memory")
    security = _table(data, "security")
    required_scanners_value = security.get(
        "required_scanners", ["dependency", "license", "sast"]
    )
    if not isinstance(required_scanners_value, list) or any(
        not isinstance(item, str) for item in required_scanners_value
    ):
        raise ConfigError("security.required_scanners must be an array of strings")
    required_scanners = tuple(required_scanners_value)
    if len(set(required_scanners)) != len(required_scanners):
        raise ConfigError("duplicate scanner in security.required_scanners")
    unknown_scanners = set(required_scanners) - SUPPORTED_SCANNERS
    if unknown_scanners:
        raise ConfigError(f"unsupported scanner: {min(unknown_scanners)}")
    scanner_commands_table = _table(security, "scanner_commands")
    scanner_commands: dict[str, tuple[str, ...]] = {}
    for scanner in SUPPORTED_SCANNERS:
        value = scanner_commands_table.get(scanner, [])
        if not isinstance(value, list):
            raise ConfigError(
                f"security.scanner_commands.{scanner} must be an argument array"
            )
        command = tuple(value)
        if any(not isinstance(item, str) or not item for item in command):
            raise ConfigError(
                f"security.scanner_commands.{scanner} must be an argument array"
            )
        scanner_commands[scanner] = command
    scanner_support_table = _table(security, "scanner_support_paths")
    scanner_versions_table = _table(security, "scanner_version_commands")
    scanner_support_paths: dict[str, tuple[str, ...]] = {}
    scanner_version_commands: dict[str, tuple[str, ...]] = {}
    for scanner in SUPPORTED_SCANNERS:
        value = scanner_support_table.get(scanner, [])
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item for item in value
        ):
            raise ConfigError(
                f"security.scanner_support_paths.{scanner} must be a path array"
            )
        scanner_support_paths[scanner] = tuple(value)
        version_value = scanner_versions_table.get(scanner, [])
        if not isinstance(version_value, list) or any(
            not isinstance(item, str) or not item for item in version_value
        ):
            raise ConfigError(
                f"security.scanner_version_commands.{scanner} must be an argument array"
            )
        scanner_version_commands[scanner] = tuple(version_value)
    require_independent = _boolean(
        review.get("require_independent_provider", True),
        "review.require_independent_provider",
    )
    if not require_independent:
        raise ConfigError("review.require_independent_provider must be true")
    return ProjectConfig(
        name=name.strip(),
        security_profile=security_profile,
        commands=_load_commands(_table(data, "commands")),
        review=ReviewConfig(
            enabled=_boolean(review.get("enabled", True), "review.enabled"),
            require_independent_provider=require_independent,
            max_package_bytes=_positive_int(
                review.get("max_package_bytes", 500_000),
                "review.max_package_bytes",
            ),
            provider_order=provider_order,
            provider_commands=MappingProxyType(provider_commands),
            max_estimated_tokens=_positive_int(review.get("max_estimated_tokens", 64000),
                                               "review.max_estimated_tokens"),
            partition_enabled=_boolean(review.get("partition_enabled", False), "review.partition_enabled"),
            max_aggregate_bytes=_positive_int(review.get("max_aggregate_bytes", 2500000), "review.max_aggregate_bytes"),
            max_aggregate_tokens=_positive_int(review.get("max_aggregate_tokens", 800000), "review.max_aggregate_tokens"),
            partition_target_bytes=_positive_int(review.get("partition_target_bytes", 250000), "review.partition_target_bytes"),
        ),
        memory=MemoryConfig(
            enabled=_boolean(memory.get("enabled", True), "memory.enabled"),
            startup_char_budget=_positive_int(
                memory.get("startup_char_budget", 4000),
                "memory.startup_char_budget",
            ),
            local_retention_days=_positive_int(
                memory.get("local_retention_days", 90),
                "memory.local_retention_days",
            ),
            startup_estimated_token_budget=_positive_int(
                memory.get("startup_estimated_token_budget", 1200),
                "memory.startup_estimated_token_budget"),
        ),
        security=SecurityConfig(
            required_scanners=required_scanners,
            scanner_commands=MappingProxyType(scanner_commands),
            scanner_version_commands=MappingProxyType(scanner_version_commands),
            scanner_support_paths=MappingProxyType(scanner_support_paths),
        ),
    )


def load_config_at_revision(root: str | Path, revision: str) -> ProjectConfig:
    repository = Path(root).resolve()
    result = subprocess.run(
        ("git", "show", f"{revision}:.agent/config.toml"),
        cwd=repository,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ConfigError("trusted base does not contain a valid .agent/config.toml")
    with tempfile.TemporaryDirectory(prefix="agent-trusted-config-") as directory:
        path = Path(directory) / "config.toml"
        path.write_bytes(result.stdout)
        return load_config(path)


def config_text_from_answers(data: object) -> str:
    if not isinstance(data, dict) or set(data) != {
        "project",
        "commands",
        "review",
        "memory",
        "security",
    }:
        raise ConfigError(
            "init answers must contain project, commands, review, security, and memory"
        )
    project = data["project"]
    commands = data["commands"]
    review = data["review"]
    memory = data["memory"]
    security = data["security"]
    if not all(
        isinstance(value, dict)
        for value in (project, commands, review, memory, security)
    ):
        raise ConfigError("init answer sections must be objects")
    if set(project) != {"name", "security_profile"}:
        raise ConfigError("project answers must contain name and security_profile")
    if set(review) - {"max_estimated_tokens", "partition_enabled", "max_aggregate_bytes", "max_aggregate_tokens", "partition_target_bytes"} != {
        "enabled",
        "require_independent_provider",
        "max_package_bytes",
        "provider_order",
        "provider_commands",
    }:
        raise ConfigError("review answers do not match the supported contract")
    if set(memory) - {"startup_estimated_token_budget"} != {"enabled", "startup_char_budget", "local_retention_days"}:
        raise ConfigError("memory answers do not match the supported contract")
    if set(security) != {
        "required_scanners",
        "scanner_commands",
        "scanner_version_commands",
        "scanner_support_paths",
    }:
        raise ConfigError("security answers do not match the supported contract")
    required_commands = {
        "format_check",
        "lint",
        "test_changed",
        "test_full",
        "build",
        "smoke",
    }
    if set(commands) != required_commands:
        raise ConfigError("commands answers must define every supported command")

    def string(value: object) -> str:
        if not isinstance(value, str):
            raise ConfigError("project string answers must be strings")
        return json.dumps(value)

    def boolean(value: object) -> str:
        if not isinstance(value, bool):
            raise ConfigError("boolean init answer must be true or false")
        return "true" if value else "false"

    lines = [
        "[project]",
        f"name = {string(project.get('name'))}",
        f"security_profile = {string(project.get('security_profile'))}",
        "",
        "[commands]",
    ]
    for name in sorted(required_commands):
        value = commands[name]
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item for item in value
        ):
            raise ConfigError(f"commands.{name} must be an array of arguments")
        lines.append(f"{name} = {json.dumps(value)}")
    provider_order = review.get("provider_order")
    if not isinstance(provider_order, list):
        raise ConfigError("review.provider_order must be an array")
    provider_commands = review.get("provider_commands")
    if not isinstance(provider_commands, dict) or set(provider_commands) != SUPPORTED_PROVIDERS:
        raise ConfigError("review.provider_commands must define claude, codex, and gemini")
    scanner_commands = security.get("scanner_commands")
    if not isinstance(scanner_commands, dict) or set(scanner_commands) != SUPPORTED_SCANNERS:
        raise ConfigError(
            "security.scanner_commands must define dependency, license, sast, iac, and container"
        )
    scanner_support_paths = security.get("scanner_support_paths")
    if (
        not isinstance(scanner_support_paths, dict)
        or set(scanner_support_paths) != SUPPORTED_SCANNERS
    ):
        raise ConfigError(
            "security.scanner_support_paths must define dependency, license, sast, iac, and container"
        )
    scanner_version_commands = security.get("scanner_version_commands")
    if (
        not isinstance(scanner_version_commands, dict)
        or set(scanner_version_commands) != SUPPORTED_SCANNERS
    ):
        raise ConfigError(
            "security.scanner_version_commands must define dependency, license, sast, iac, and container"
        )
    lines.extend(
        [
            "",
            "[review]",
            f"enabled = {boolean(review.get('enabled'))}",
            ("require_independent_provider = "
            f"{boolean(review.get('require_independent_provider'))}"),
            f"max_package_bytes = {review.get('max_package_bytes')}",
            f"max_estimated_tokens = {review.get('max_estimated_tokens', 64000)}",
            f"partition_enabled = {boolean(review.get('partition_enabled', False))}",
            f"max_aggregate_bytes = {review.get('max_aggregate_bytes', 2500000)}",
            f"max_aggregate_tokens = {review.get('max_aggregate_tokens', 800000)}",
            f"partition_target_bytes = {review.get('partition_target_bytes', 250000)}",
            f"provider_order = {json.dumps(provider_order)}",
            "",
            "[review.provider_commands]",
            *(f"{provider} = {json.dumps(provider_commands[provider])}" for provider in sorted(SUPPORTED_PROVIDERS)),
            "",
            "[documentation]",
            'system_html = "docs/architecture/system.html"',
            "",
            "[security]",
            f"required_scanners = {json.dumps(security.get('required_scanners'))}",
            "",
            "[security.scanner_commands]",
            *(f"{scanner} = {json.dumps(scanner_commands[scanner])}" for scanner in sorted(SUPPORTED_SCANNERS)),
            "",
            "[security.scanner_version_commands]",
            *(f"{scanner} = {json.dumps(scanner_version_commands[scanner])}" for scanner in sorted(SUPPORTED_SCANNERS)),
            "",
            "[security.scanner_support_paths]",
            *(f"{scanner} = {json.dumps(scanner_support_paths[scanner])}" for scanner in sorted(SUPPORTED_SCANNERS)),
            "",
            "[memory]",
            f"enabled = {boolean(memory.get('enabled'))}",
            f"startup_char_budget = {memory.get('startup_char_budget')}",
            f"startup_estimated_token_budget = {memory.get('startup_estimated_token_budget', 1200)}",
            f"local_retention_days = {memory.get('local_retention_days')}",
            "",
        ]
    )
    text = "\n".join(lines)
    with tempfile.TemporaryDirectory() as directory:
        candidate = Path(directory) / "config.toml"
        candidate.write_text(text, encoding="utf-8")
        load_config(candidate)
    return text
