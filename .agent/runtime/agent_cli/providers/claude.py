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


class ClaudeAdapter:
    provider = "claude"

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
        raw = self.command or ((self.executable,) if self.executable else ("claude",))
        executable = shutil.which(raw[0]) or (raw[0] if Path(raw[0]).is_file() else None)
        if executable is None:
            raise FileNotFoundError("claude executable not found")
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
            help_arguments=("--help",),
            json_markers=("--output-format", "--json-schema"),
            read_only_markers=("--restricted", "--no-session-persistence"),
            repository_root=self.repository_root,
        )

    def build_argv(self, request: ReviewRequest) -> tuple[str, ...]:
        command = self._resolved_command()
        schema = request.output_schema_path.read_text(encoding="utf-8")
        return (
            *command,
            "--print",
            "--output-format",
            "json",
            "--json-schema",
            schema,
            "--permission-mode",
            "plan",
            "--permission-prompts",
            "none",
            "--tools",
            "Read",
            "--no-session-persistence",
            "--strict-mcp-config",
            "--restricted",
            "--safe-mode",
            "Read instructions.md and follow it exactly.",
        )

    def parse(self, raw: str) -> ProviderResult:
        if len(raw.encode("utf-8", errors="replace")) > 1_000_000:
            return ProviderResult.invalid(self.provider, raw, "provider output exceeds limit")
        try:
            payload = json.loads(raw)
            if isinstance(payload, dict) and "structured_output" in payload:
                payload = payload["structured_output"]
            elif isinstance(payload, dict) and isinstance(payload.get("result"), str):
                payload = json.loads(payload["result"])
        except (json.JSONDecodeError, TypeError):
            return ProviderResult.invalid(self.provider, raw)
        return validated_result(self.provider, payload, raw)

    def review(self, request: ReviewRequest) -> ProviderResult:
        return invoke_provider(
            provider=self.provider,
            argv=self.build_argv(request),
            request=request,
            parser=self.parse,
            support_paths=self._resolved_command()[1:],
        )
