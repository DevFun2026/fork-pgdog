from __future__ import annotations

import json
from pathlib import Path
import re
import shutil

from agent_cli.providers.base import (
    Capability,
    ProviderPolicyError,
    ProviderResult,
    ReviewRequest,
    invoke_provider,
    probe_capability,
    validated_result,
)


class GeminiAdapter:
    """Gemini model family, executed by Antigravity CLI (agy)."""

    provider = "gemini"
    default_model = "gemini-3.1-pro-high"

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
        raw = self.command or ((self.executable,) if self.executable else ("agy",))
        executable = shutil.which(raw[0]) or (raw[0] if Path(raw[0]).is_file() else None)
        if executable is None:
            raise FileNotFoundError("agy executable not found (Gemini provider)")
        return (executable, *raw[1:])

    def _model_arguments(self, command: tuple[str, ...]) -> tuple[str, ...]:
        models = []
        for index, argument in enumerate(command[1:], start=1):
            if argument == "--model":
                models.append(command[index + 1] if index + 1 < len(command) else "")
            elif argument.startswith("--model="):
                models.append(argument.partition("=")[2])
        if not models:
            return ("--model", self.default_model)
        if len(models) != 1 or not re.fullmatch(r"gemini-[a-z0-9][a-z0-9.-]*", models[0]):
            raise ProviderPolicyError("agy review requires exactly one Gemini --model")
        return ()

    def detect(self) -> Capability:
        try:
            command = self._resolved_command()
            self._model_arguments(command)
        except (FileNotFoundError, ProviderPolicyError) as exc:
            return Capability(self.provider, False, None, None, False, False, str(exc))
        return probe_capability(
            provider=self.provider,
            executable=command[0],
            prefix_arguments=command[1:],
            help_arguments=("--help",),
            json_markers=("--print", "--output-format", "json", "--json-schema", "--model"),
            # Plan is advisory. The outer OS sandbox enforces package read-only.
            read_only_markers=("--mode", "plan"),
            repository_root=self.repository_root,
        )

    def build_argv(self, request: ReviewRequest) -> tuple[str, ...]:
        command = self._resolved_command()
        return (
            *command,
            *self._model_arguments(command),
            "--print",
            "Read instructions.md and follow it exactly.",
            "--output-format",
            "json",
            "--json-schema",
            str(request.output_schema_path),
            "--mode",
            "plan",
        )

    def parse(self, raw: str) -> ProviderResult:
        if len(raw.encode("utf-8", errors="replace")) > 1_000_000:
            return ProviderResult.invalid(self.provider, raw, "provider output exceeds limit")
        try:
            payload = json.loads(raw)
            if (not isinstance(payload, dict) or payload.get("status") != "SUCCESS"
                    or payload.get("error") or "structured_output" not in payload):
                return ProviderResult.invalid(self.provider, raw, "agy did not return successful schema output")
            structured = payload["structured_output"]
            if "response" in payload:
                response = payload["response"]
                if not isinstance(response, str) or not response.strip():
                    return ProviderResult.invalid(self.provider, raw, "agy response is empty or invalid")
                # Native AGY may concatenate repeated terminal objects, including
                # display metadata. Every object must agree with the strict result.
                decoder = json.JSONDecoder()
                remaining = response.strip()
                while remaining:
                    item, end = decoder.raw_decode(remaining)
                    if (not isinstance(item, dict)
                            or set(item) - {"verdict", "findings", "toolAction", "toolSummary"}
                            or any(not isinstance(item[key], str)
                                   for key in ("toolAction", "toolSummary") if key in item)
                            or {key: value for key, value in item.items()
                                if key not in {"toolAction", "toolSummary"}} != structured):
                        return ProviderResult.invalid(self.provider, raw, "agy output fields disagree")
                    remaining = remaining[end:].strip()
        except (json.JSONDecodeError, TypeError):
            return ProviderResult.invalid(self.provider, raw)
        try:
            return validated_result(self.provider, structured, raw)
        except (TypeError, ValueError):
            return ProviderResult.invalid(self.provider, raw, "agy findings do not match schema")

    def review(self, request: ReviewRequest) -> ProviderResult:
        return invoke_provider(
            provider=self.provider,
            argv=self.build_argv(request),
            request=request,
            parser=self.parse,
            support_paths=self._resolved_command()[1:],
        )
