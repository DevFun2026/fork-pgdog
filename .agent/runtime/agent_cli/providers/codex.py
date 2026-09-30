from __future__ import annotations

import json
from pathlib import Path
import shutil

from agent_cli.providers.base import (
    Capability,
    ProviderResult,
    ReviewRequest,
    invoke_provider,
    probe_capability,
    validated_result,
)


class CodexAdapter:
    provider = "codex"

    def __init__(
        self,
        executable: str | None = None,
        command: tuple[str, ...] | None = None,
        repository_root: Path | None = None,
    ):
        self.executable = executable
        self.command = command
        self.repository_root = (repository_root or Path.cwd()).resolve()

    def _resolved_command(self) -> tuple[str, ...]:
        if self.executable is not None and self.command is None:
            return (self.executable,)
        raw = self.command or ((self.executable,) if self.executable else ("codex",))
        executable = shutil.which(raw[0]) or (raw[0] if Path(raw[0]).is_file() else None)
        if executable is None:
            raise FileNotFoundError("codex executable not found")
        return (executable, *raw[1:])

    def detect(self) -> Capability:
        try:
            command = self._resolved_command()
        except FileNotFoundError:
            command = (None,)
        return probe_capability(
            provider=self.provider,
            executable=command[0],
            prefix_arguments=command[1:],
            help_arguments=("exec", "--help"),
            json_markers=("--output-schema", "--json"),
            read_only_markers=("--sandbox", "read-only", "--ephemeral"),
            repository_root=self.repository_root,
        )

    def build_argv(self, request: ReviewRequest) -> tuple[str, ...]:
        command = self._resolved_command()
        return (
            *command,
            "--config",
            'shell_environment_policy.inherit="none"',
            "--config",
            "shell_environment_policy.ignore_default_excludes=false",
            "exec",
            "--ephemeral",
            "--ignore-user-config",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--output-schema",
            str(request.output_schema_path),
            "--json",
            "Read instructions.md and follow it exactly.",
        )

    def parse(self, raw: str) -> ProviderResult:
        if len(raw.encode("utf-8", errors="replace")) > 1_000_000:
            return ProviderResult.invalid(self.provider, raw, "provider output exceeds limit")
        candidates: list[object] = []
        try:
            for line in raw.splitlines():
                if not line.strip():
                    continue
                event = json.loads(line)
                if (
                    isinstance(event, dict)
                    and event.get("type") == "item.completed"
                    and isinstance(event.get("item"), dict)
                    and event["item"].get("type") == "agent_message"
                ):
                    try:
                        candidates.append(json.loads(event["item"]["text"]))
                    except (json.JSONDecodeError, TypeError):
                        # Codex may emit human-readable progress messages before
                        # the schema-constrained terminal response.
                        continue
                elif isinstance(event, dict) and event.get("type") == "result":
                    candidates.append(event.get("result"))
        except (json.JSONDecodeError, KeyError, TypeError):
            return ProviderResult.invalid(self.provider, raw)

        valid = [
            result
            for payload in candidates
            if (result := validated_result(self.provider, payload, raw)).status
            == "completed"
        ]
        if len(valid) != 1:
            return ProviderResult.invalid(
                self.provider, raw, "expected exactly one schema-valid terminal result"
            )
        return valid[0]

    def review(self, request: ReviewRequest) -> ProviderResult:
        return invoke_provider(
            provider=self.provider,
            argv=self.build_argv(request),
            request=request,
            parser=self.parse,
            support_paths=self._resolved_command()[1:],
        )
