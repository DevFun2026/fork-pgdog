from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import platform
import subprocess
import sys

from agent_cli.config import (
    ConfigError,
    config_text_from_answers,
    load_config,
    load_config_at_revision,
)
from agent_cli.context import ESTIMATOR, PROFILES, report as context_report
from agent_cli.workflow import workflow_guide
from agent_cli.adapters import AdapterError, build_adapters, check_adapters
from agent_cli.docs import (
    check_docs,
    committed_documentation_metadata,
    git_documentation_metadata,
    write_docs,
)
from agent_cli.errors import ExitCode
from agent_cli.governance import GovernanceBaseError, resolve_trusted_base
from agent_cli.memory.service import MemoryService, candidate_from_dict
from agent_cli.licenses import audit_sources
from agent_cli.paths import PathPolicyError, atomic_write, resolve_inside
from agent_cli.process import run_command
from agent_cli.providers import ClaudeAdapter, CodexAdapter, GeminiAdapter
from agent_cli.providers.base import ProviderPolicyError
from agent_cli.redaction import redact
from agent_cli.review.models import ReviewPackageRequest
from agent_cli.review.adjudication import adjudicate_findings
from agent_cli.review.orchestrator import ReviewOrchestrator
from agent_cli.review.package import (
    ReviewPackageBlocked,
    load_package,
    read_review_requirements,
    package_usage,
)
from agent_cli.security import SecurityPolicyError, assess_repository, validate_signed_approval
from agent_cli.skills import SkillValidationError, load_skills
from agent_cli.verify import (
    MERGE_COMMANDS,
    collect_fresh_verification_evidence,
    git_identity,
    read_workflow_state,
    run_gate,
    tool_identity,
)


ROOT = Path(__file__).resolve().parents[3]


def positive_argument(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent")
    parser.add_argument("--version", action="store_true")
    commands = parser.add_subparsers(dest="command")

    init = commands.add_parser("init")
    init.add_argument("--answers", type=Path)

    workflow = commands.add_parser("workflow")
    workflow_commands = workflow.add_subparsers(dest="workflow_command", required=True)
    workflow_status = workflow_commands.add_parser("status")
    workflow_status.add_argument("--json", action="store_true", dest="as_json")
    guide = workflow_commands.add_parser("guide")
    guide.add_argument("--task", choices=("content", "behavior", "interface", "architecture", "security"), required=True)

    verify = commands.add_parser("verify")
    verify.add_argument("level", choices=("quick", "review", "merge", "release"))
    verify.add_argument("--json", action="store_true", dest="as_json")
    verify.add_argument("--timeout", type=positive_argument, default=60,
                        help="maximum seconds per configured command (default: 60)")

    docs = commands.add_parser("docs")
    docs_commands = docs.add_subparsers(dest="docs_command", required=True)
    docs_commands.add_parser("build")
    docs_commands.add_parser("check")

    doctor = commands.add_parser("doctor")
    doctor.add_argument("--json", action="store_true", dest="as_json")
    doctor.add_argument("--providers", action="store_true")
    doctor.add_argument("--ci", action="store_true")

    security = commands.add_parser("security")
    security.add_argument("--json", action="store_true", dest="as_json")
    security.add_argument("--base")
    security.add_argument("--head", default="HEAD")
    security.add_argument("--approval-evidence", type=Path)
    security.add_argument("--approval-signature", type=Path)

    release = commands.add_parser("release")
    release_commands = release.add_subparsers(dest="release_command", required=True)
    release_record = release_commands.add_parser("record")
    release_record.add_argument(
        "--artifact",
        required=True,
        choices=("release-notes", "migration-rollback", "residual-risks"),
    )
    release_record.add_argument("--file", type=Path, required=True)
    release_smoke = release_commands.add_parser("record-clean-smoke")
    release_smoke.add_argument("--head", required=True)
    release_scanner = release_commands.add_parser("run-scanner")
    release_scanner.add_argument(
        "--scanner",
        required=True,
        choices=("dependency", "license", "sast", "iac", "container"),
    )
    release_scanner.add_argument("--timeout", type=float, default=300.0)

    memory = commands.add_parser("memory")
    memory_commands = memory.add_subparsers(dest="memory_command", required=True)
    memory_commands.add_parser("init")
    memory_doctor = memory_commands.add_parser("doctor")
    memory_doctor.add_argument("--json", action="store_true", dest="as_json")
    checkpoint = memory_commands.add_parser("checkpoint")
    checkpoint.add_argument("--file", type=Path)
    bootstrap = memory_commands.add_parser("bootstrap")
    bootstrap.add_argument("--query", required=True)
    bootstrap.add_argument("--char-budget", type=positive_argument)
    bootstrap.add_argument("--profile", choices=tuple(PROFILES), default="standard")
    bootstrap.add_argument("--limit", type=positive_argument)
    bootstrap.add_argument("--report", action="store_true")
    search = memory_commands.add_parser("search")
    search.add_argument("query")
    search.add_argument("--include-stale", action="store_true")
    search.add_argument("--profile", choices=tuple(PROFILES), default="standard")
    search.add_argument("--limit", type=positive_argument)
    search.add_argument("--char-budget", type=positive_argument)
    timeline = memory_commands.add_parser("timeline")
    timeline.add_argument("id")
    show = memory_commands.add_parser("show")
    show.add_argument("ids", nargs="+")
    show.add_argument("--char-budget", type=positive_argument, default=16000)
    show.add_argument("--max-estimated-tokens", type=positive_argument, default=4800)
    promote = memory_commands.add_parser("promote")
    promote.add_argument("id")
    supersede = memory_commands.add_parser("supersede")
    supersede.add_argument("old_id")
    supersede.add_argument("new_id")
    forget = memory_commands.add_parser("forget")
    forget.add_argument("id")
    forget.add_argument("--canonical", action="store_true")
    forget.add_argument("--reason")
    memory_commands.add_parser("rebuild-index")
    hook_start = memory_commands.add_parser("hook-start")
    hook_start.add_argument("--provider", required=True, choices=("claude", "gemini"))
    hook_reminder = memory_commands.add_parser("hook-reminder")
    hook_reminder.add_argument("--provider", required=True, choices=("claude", "gemini"))
    export = memory_commands.add_parser("export")
    export.add_argument("--output", type=Path)
    import_command = memory_commands.add_parser("import")
    import_command.add_argument("file", type=Path)

    review = commands.add_parser("review")
    review.add_argument("--base")
    review.add_argument("--head", default="HEAD")
    review.add_argument(
        "--author-provider", required=True, choices=("claude", "gemini", "codex")
    )
    review.add_argument("--reviewer-provider", choices=("claude", "gemini", "codex"))
    review.add_argument("--context", action="append", default=[])
    review.add_argument("--requirements", type=Path)
    review.add_argument("--approve-manifest")
    review.add_argument("--package", type=Path)
    review.add_argument("--max-package-bytes", type=int)
    review.add_argument("--profile", choices=tuple(PROFILES), default="standard")
    review.add_argument("--max-estimated-tokens", type=positive_argument)

    adjudication = commands.add_parser("adjudicate")
    adjudication.add_argument("--package", type=Path, required=True)
    adjudication.add_argument("--file", type=Path, required=True)

    adapters = commands.add_parser("adapters")
    adapter_commands = adapters.add_subparsers(dest="adapters_command", required=True)
    adapter_commands.add_parser("build")
    adapter_commands.add_parser("check")

    skills = commands.add_parser("skills")
    skill_commands = skills.add_subparsers(dest="skills_command", required=True)
    skill_commands.add_parser("check")

    licenses = commands.add_parser("licenses")
    license_commands = licenses.add_subparsers(dest="licenses_command", required=True)
    license_audit = license_commands.add_parser("audit")
    license_audit.add_argument("--json", action="store_true", dest="as_json")
    license_check = license_commands.add_parser("check")
    license_check.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version and args.command is None:
        version = (ROOT / ".agent/VERSION").read_text(encoding="utf-8").strip()
        print(f"agent-project-template {version}")
        return ExitCode.OK
    if args.command == "init":
        try:
            if args.answers is not None:
                answers_path = resolve_inside(ROOT, args.answers)
                if not answers_path.is_file() or answers_path.is_symlink():
                    raise ConfigError("init answers must be a regular file inside the repository")
                try:
                    answers = json.loads(answers_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise ConfigError(f"cannot load init answers: {exc}") from exc
                atomic_write(
                    ROOT / ".agent/config.toml",
                    config_text_from_answers(answers),
                )
            load_config(ROOT / ".agent/config.toml")
            load_skills(ROOT / ".agent/skills")
            build_adapters(ROOT)
            generated_at, commit = committed_documentation_metadata(ROOT)
            if not check_docs(ROOT, generated_at=generated_at, commit=commit).ok:
                generated_at, commit = git_documentation_metadata(ROOT)
                write_docs(ROOT, generated_at=generated_at, commit=commit)
            MemoryService(ROOT).init()
        except (
            ConfigError,
            SkillValidationError,
            AdapterError,
            PathPolicyError,
            ValueError,
        ) as exc:
            print(json.dumps({"status": "blocked", "reasons": [str(exc)]}))
            return ExitCode.POLICY_BLOCKED
        print("initialized reviewed agent configuration and generated artifacts")
        return ExitCode.OK
    if args.command == "workflow":
        if args.workflow_command == "guide":
            print(json.dumps(workflow_guide(args.task), sort_keys=True))
            return ExitCode.OK
        state = read_workflow_state(ROOT)
        if args.as_json:
            print(json.dumps({"state": state.value}, sort_keys=True))
        else:
            print(state.value)
        return ExitCode.OK
    if args.command == "doctor":
        providers = {
            adapter.provider: asdict(adapter.detect())
            for adapter in (
                ClaudeAdapter(repository_root=ROOT),
                GeminiAdapter(repository_root=ROOT),
                CodexAdapter(repository_root=ROOT),
            )
        }
        report = {
            "python": platform.python_version(),
            "python_supported": sys.version_info >= (3, 11),
            "platform": platform.system().lower(),
            "ci": args.ci,
            "providers": providers,
        }
        print(json.dumps(report, sort_keys=True) if args.as_json else report)
        return ExitCode.OK if report["python_supported"] else ExitCode.INCOMPLETE
    if args.command == "verify":
        try:
            config = load_config(ROOT / ".agent/config.toml")
        except ConfigError as exc:
            print(json.dumps({"status": "incomplete", "reasons": [str(exc)]}))
            return ExitCode.INCOMPLETE
        result = run_gate(args.level, config, ROOT, timeout=args.timeout)
        if args.as_json:
            print(json.dumps(result.to_dict(), sort_keys=True))
        else:
            print(f"{result.level}: {result.status}")
            for reason in result.reasons:
                print(f"- {reason}")
        if result.status == "passed":
            return ExitCode.OK
        if result.status == "blocked":
            return ExitCode.POLICY_BLOCKED
        return ExitCode.INCOMPLETE
    if args.command == "security":
        try:
            config = load_config(ROOT / ".agent/config.toml")
            trusted_base, trusted_head = resolve_trusted_base(
                ROOT, head=args.head, requested_base=args.base
            )
            trusted_config = load_config_at_revision(ROOT, trusted_base)
            profile_rank = {"baseline": 0, "standard": 1, "high": 2}
            approved_profile = max(
                (config.security_profile, trusted_config.security_profile),
                key=profile_rank.__getitem__,
            )
            assessment = assess_repository(
                ROOT,
                approved_profile=approved_profile,
                base=trusted_base,
                head=trusted_head,
            )
            approval = None
            if (args.approval_evidence is None) != (args.approval_signature is None):
                raise SecurityPolicyError(
                    "security approval requires both evidence and signature"
                )
            if args.approval_evidence is not None:
                approval_path = resolve_inside(ROOT, args.approval_evidence)
                signature_path = resolve_inside(ROOT, args.approval_signature)
                if (
                    not approval_path.is_file()
                    or approval_path.is_symlink()
                    or not signature_path.is_file()
                    or signature_path.is_symlink()
                ):
                    raise SecurityPolicyError(
                        "security approval and signature must be regular repository files"
                    )
                approval = validate_signed_approval(
                    ROOT, assessment, approval_path, signature_path
                )
        except (
            ConfigError,
            GovernanceBaseError,
            SecurityPolicyError,
            OSError,
            PathPolicyError,
        ) as exc:
            print(json.dumps({"status": "blocked", "reasons": [str(exc)]}))
            return ExitCode.POLICY_BLOCKED
        atomic_write(
            ROOT / ".agent/.runs/security-clearance.json",
            json.dumps(
                {
                    "status": "passed" if approval else "incomplete",
                    "reason": (
                        "independent security approval evidence is bound"
                        if approval
                        else "scope and review lenses are assessed; independent security clearance is still required"
                    ),
                    "approval_evidence": approval,
                    **assessment.to_dict(),
                },
                sort_keys=True,
            )
            + "\n",
        )
        assessment_document = json.loads(
            json.dumps(assessment.to_dict(), sort_keys=True)
        )
        assessment_sha256 = sha256(
            json.dumps(
                assessment_document, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        if args.as_json:
            print(
                json.dumps(
                    {
                        "assessment": assessment_document,
                        "assessment_sha256": assessment_sha256,
                        "clearance_status": "passed" if approval else "incomplete",
                    },
                    sort_keys=True,
                )
            )
        else:
            print(f"security profile: {assessment.assessed_profile}")
            print(f"reviewed scope: {', '.join(assessment.reviewed_scope)}")
            print(f"residual risks: {len(assessment.residual_risks)}")
        return ExitCode.OK
    if args.command == "release":
        head_sha, worktree_diff_sha256 = git_identity(ROOT)
        release_exit = ExitCode.OK
        if args.release_command == "record-clean-smoke":
            status = subprocess.run(
                ("git", "status", "--porcelain=v1", "--untracked-files=all"),
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            if (
                args.head != head_sha
                or worktree_diff_sha256 != sha256(b"").hexdigest()
                or status.returncode != 0
                or status.stdout.strip()
            ):
                print(json.dumps({"status": "blocked", "reasons": ["clean smoke does not match a clean current HEAD"]}))
                return ExitCode.POLICY_BLOCKED
            artifact_name = "clean-checkout-smoke"
            payload = {
                "status": "passed",
                "head_sha": head_sha,
                "working_tree_diff_sha256": worktree_diff_sha256,
                "method": "git archive clean-checkout release smoke",
            }
        elif args.release_command == "run-scanner":
            try:
                config = load_config(ROOT / ".agent/config.toml")
                command = config.security.scanner_commands[args.scanner]
                if not command:
                    raise ValueError(f"scanner command is not configured: {args.scanner}")
                version_command = config.security.scanner_version_commands[args.scanner]
                if not version_command:
                    raise ValueError(
                        f"scanner version command is not configured: {args.scanner}"
                    )
                support_paths = config.security.scanner_support_paths[args.scanner]
                scanner_tool_identity = tool_identity(
                    command,
                    ROOT,
                    version_argv=version_command,
                    support_paths=support_paths,
                )
                started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                result = run_command(command, cwd=ROOT, timeout=args.timeout)
            except (ConfigError, OSError, ValueError) as exc:
                print(json.dumps({"status": "blocked", "reasons": [str(exc)]}))
                return ExitCode.POLICY_BLOCKED
            if result.timed_out:
                scanner_status = "timeout"
                release_exit = ExitCode.INCOMPLETE
            elif result.exit_code == 0:
                scanner_status = "passed"
            else:
                scanner_status = "failed"
                release_exit = ExitCode.POLICY_BLOCKED
            output_payload = {
                "scanner": args.scanner,
                "status": scanner_status,
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "started_at": started_at,
                "duration_ms": result.duration_ms,
                "stdout": redact(result.stdout).text,
                "stderr": redact(result.stderr).text,
            }
            output_path = ROOT / f".agent/.runs/scanners/{args.scanner}.json"
            atomic_write(output_path, json.dumps(output_payload, sort_keys=True) + "\n")
            output_bytes = output_path.read_bytes()
            artifact_name = "security-checks"
            existing_path = ROOT / ".agent/.runs/security-checks.json"
            existing = {}
            if existing_path.is_file():
                try:
                    loaded = json.loads(existing_path.read_text(encoding="utf-8"))
                    if (
                        isinstance(loaded, dict)
                        and loaded.get("head_sha") == head_sha
                        and loaded.get("working_tree_diff_sha256") == worktree_diff_sha256
                        and loaded.get("required") == list(config.security.required_scanners)
                    ):
                        existing = loaded
                except (OSError, json.JSONDecodeError):
                    pass
            results = existing.get("results", {})
            if not isinstance(results, dict):
                results = {}
            results[args.scanner] = {
                "status": scanner_status,
                "tool_version": scanner_tool_identity,
                "command_sha256": sha256(
                    json.dumps(list(command), separators=(",", ":")).encode("utf-8")
                ).hexdigest(),
                "output_path": output_path.relative_to(ROOT).as_posix(),
                "output_sha256": sha256(output_bytes).hexdigest(),
            }
            payload = {
                "head_sha": head_sha,
                "working_tree_diff_sha256": worktree_diff_sha256,
                "required": list(config.security.required_scanners),
                "results": results,
            }
        else:
            try:
                source = resolve_inside(ROOT, args.file)
                if not source.is_file() or source.is_symlink():
                    raise ValueError("release evidence must be a regular repository file")
                content = source.read_bytes()
                if not content.strip():
                    raise ValueError("release evidence is empty")
            except (OSError, PathPolicyError, ValueError) as exc:
                print(json.dumps({"status": "blocked", "reasons": [str(exc)]}))
                return ExitCode.POLICY_BLOCKED
            artifact_name = args.artifact
            payload = {
                "status": "passed",
                "head_sha": head_sha,
                "working_tree_diff_sha256": worktree_diff_sha256,
                "source_path": source.relative_to(ROOT).as_posix(),
                "source_sha256": sha256(content).hexdigest(),
            }
        atomic_write(
            ROOT / f".agent/.runs/{artifact_name}.json",
            json.dumps(payload, sort_keys=True) + "\n",
        )
        print(json.dumps(payload, sort_keys=True))
        return release_exit
    if args.command == "docs":
        if args.docs_command == "build":
            generated_at, commit = git_documentation_metadata(ROOT)
            write_docs(ROOT, generated_at=generated_at, commit=commit)
            head_sha, worktree_diff_sha256 = git_identity(ROOT)
            atomic_write(
                ROOT / ".agent/.runs/documentation-impact.json",
                json.dumps(
                    {
                        "status": "updated",
                        "files": [
                            "docs/architecture/system-summary.md",
                            "docs/architecture/system.html",
                        ],
                        "head_sha": head_sha,
                        "working_tree_diff_sha256": worktree_diff_sha256,
                    },
                    sort_keys=True,
                )
                + "\n",
            )
            print("generated docs/architecture/system-summary.md and system.html")
            return ExitCode.OK
        generated_at, commit = committed_documentation_metadata(ROOT)
        result = check_docs(ROOT, generated_at=generated_at, commit=commit)
        if result.ok:
            head_sha, worktree_diff_sha256 = git_identity(ROOT)
            atomic_write(
                ROOT / ".agent/.runs/documentation-impact.json",
                json.dumps(
                    {
                        "status": "none",
                        "rationale": "generated architecture matches committed metadata",
                        "head_sha": head_sha,
                        "working_tree_diff_sha256": worktree_diff_sha256,
                    },
                    sort_keys=True,
                )
                + "\n",
            )
            print("architecture documentation is current")
            return ExitCode.OK
        for path in result.changed:
            print(f"stale: {path}")
        return ExitCode.POLICY_BLOCKED
    if args.command == "skills":
        try:
            skills = load_skills(ROOT / ".agent/skills")
        except SkillValidationError as exc:
            print(json.dumps({"status": "blocked", "reasons": [str(exc)]}))
            return ExitCode.POLICY_BLOCKED
        print(json.dumps({"status": "passed", "skill_count": len(skills)}, sort_keys=True))
        return ExitCode.OK
    if args.command == "licenses":
        result = audit_sources(
            ROOT / ".agent/sources/SOURCES.md",
            notice_path=ROOT / "THIRD_PARTY_NOTICES.md",
        )
        print(json.dumps(result.to_dict(), sort_keys=True) if args.as_json else result)
        return ExitCode.OK if result.ok else ExitCode.POLICY_BLOCKED
    if args.command == "adapters":
        try:
            result = (
                build_adapters(ROOT)
                if args.adapters_command == "build"
                else check_adapters(ROOT)
            )
        except AdapterError as exc:
            print(json.dumps({"status": "blocked", "reasons": [str(exc)]}))
            return ExitCode.POLICY_BLOCKED
        if result.ok:
            print("provider adapters are current")
            return ExitCode.OK
        for path in result.changed:
            print(f"stale: {path}")
        return ExitCode.POLICY_BLOCKED
    if args.command == "memory":
        service = MemoryService(ROOT)
        if args.memory_command == "init":
            print(json.dumps(service.init(), sort_keys=True))
            return ExitCode.OK
        if args.memory_command == "doctor":
            report = service.doctor()
            print(json.dumps(report, sort_keys=True) if args.as_json else report)
            return ExitCode.OK
        if args.memory_command == "checkpoint":
            raw = args.file.read_text(encoding="utf-8") if args.file else sys.stdin.read()
            candidate = candidate_from_dict(json.loads(raw))
            print(service.checkpoint(candidate).id)
            return ExitCode.OK
        if args.memory_command == "bootstrap":
            config = load_config(ROOT / ".agent/config.toml")
            profile = PROFILES[args.profile]
            budget = min(args.char_budget or config.memory.startup_char_budget, config.memory.startup_char_budget)
            token_budget = min(profile.memory_tokens, config.memory.startup_estimated_token_budget)
            content = service.bootstrap(args.query, char_budget=budget,
                limit=args.limit or profile.records, token_budget=token_budget) if config.memory.enabled else ""
            if args.report:
                print(json.dumps({**context_report(content, token_budget),
                    "profile": args.profile, "chars": len(content), "context": content}, ensure_ascii=False))
            else:
                print(content, end="")
            return ExitCode.OK
        if args.memory_command == "search":
            config = load_config(ROOT / ".agent/config.toml")
            profile = PROFILES[args.profile]
            result = service.search(args.query, include_stale=args.include_stale,
                limit=args.limit or profile.records,
                char_budget=max(2, min(args.char_budget or config.memory.startup_char_budget, config.memory.startup_char_budget)),
                token_budget=min(profile.memory_tokens, config.memory.startup_estimated_token_budget)) if config.memory.enabled else None
            print(json.dumps([asdict(row) for row in result.rows] if result else [], sort_keys=True, ensure_ascii=False))
            return ExitCode.OK
        if args.memory_command == "timeline":
            print("\n".join(service.timeline(args.id)))
            return ExitCode.OK
        if args.memory_command == "show":
            try:
                content = service.show(args.ids, char_budget=args.char_budget,
                                       token_budget=args.max_estimated_tokens)
            except ValueError as exc:
                print(json.dumps({"status": "blocked", "reasons": [str(exc)]}))
                return ExitCode.POLICY_BLOCKED
            print(content, end="")
            return ExitCode.OK
        if args.memory_command == "promote":
            print(service.promote(args.id).id)
            return ExitCode.OK
        if args.memory_command == "supersede":
            service.supersede(args.old_id, args.new_id)
            return ExitCode.OK
        if args.memory_command == "forget":
            service.forget(args.id, canonical=args.canonical, reason=args.reason)
            return ExitCode.OK
        if args.memory_command == "rebuild-index":
            service.rebuild_index()
            return ExitCode.OK
        if args.memory_command == "hook-start":
            if args.provider == "gemini":
                # AGY PreInvocation is not SessionStart: avoid repeating memory
                # at every model call. Never read the supplied transcript path.
                try:
                    payload = json.loads(sys.stdin.read(65537))
                except (ValueError, OSError):
                    payload = None
                if (not isinstance(payload, dict)
                        or type(payload.get("invocationNum")) is not int
                        or payload["invocationNum"] != 0):
                    print("{}")
                    return ExitCode.OK
            config = load_config(ROOT / ".agent/config.toml")
            context = service.bootstrap(
                "",
                char_budget=config.memory.startup_char_budget,
                startup=True, limit=5,
                token_budget=config.memory.startup_estimated_token_budget,
            ) if config.memory.enabled else ""
            if args.provider == "gemini":
                # Memory is untrusted project data, not a system instruction.
                print(json.dumps({"injectSteps": [{"userMessage": context}]} if context else {}))
                return ExitCode.OK
            print(
                json.dumps(
                    {
                        "systemMessage": "Project Memory bootstrap completed.",
                        "suppressOutput": True,
                        "hookSpecificOutput": {
                            "hookEventName": "SessionStart",
                            "additionalContext": context
                            or "Project Memory has no matching active canonical records.",
                        },
                    },
                    sort_keys=True,
                )
            )
            return ExitCode.OK
        if args.memory_command == "hook-reminder":
            if args.provider == "gemini":
                print("Consider a reviewed project-memory checkpoint before handoff; "
                      "no transcript is saved automatically.", file=sys.stderr)
                print(json.dumps({"decision": "allow"}))
                return ExitCode.OK
            print(
                json.dumps(
                    {
                        "systemMessage": (
                            "Before final handoff, checkpoint durable project learning "
                            "with ./scripts/agent memory checkpoint; review is required "
                            "before canonical promotion."
                        ),
                        "suppressOutput": False,
                    },
                    sort_keys=True,
                )
            )
            return ExitCode.OK
        if args.memory_command == "export":
            payload = service.export_redacted()
            if args.output:
                args.output.write_bytes(payload)
            else:
                sys.stdout.buffer.write(payload)
            return ExitCode.OK
        if args.memory_command == "import":
            print("\n".join(item.id for item in service.import_file(args.file)))
            return ExitCode.OK
    if args.command == "review":
        try:
            config = load_config(ROOT / ".agent/config.toml")
            trusted_base, trusted_head = resolve_trusted_base(
                ROOT, head=args.head, requested_base=args.base
            )
            trusted_config = load_config_at_revision(ROOT, trusted_base)
        except ConfigError as exc:
            print(json.dumps({"status": "blocked", "reasons": [str(exc)]}))
            return ExitCode.POLICY_BLOCKED
        except GovernanceBaseError as exc:
            print(json.dumps({"status": "blocked", "reasons": [str(exc)]}))
            return ExitCode.POLICY_BLOCKED
        review_policy = trusted_config.review
        if not review_policy.enabled:
            print(json.dumps({"status": "blocked", "reasons": ["review is disabled"]}))
            return ExitCode.POLICY_BLOCKED
        max_package_bytes = args.max_package_bytes or review_policy.max_package_bytes
        max_estimated_tokens = args.max_estimated_tokens or min(
            PROFILES[args.profile].review_tokens, review_policy.max_estimated_tokens)
        if max_estimated_tokens > review_policy.max_estimated_tokens:
            print(json.dumps({"status": "blocked", "reasons": ["estimated-token override exceeds approved limit"]}))
            return ExitCode.POLICY_BLOCKED
        if max_package_bytes > review_policy.max_package_bytes:
            print(
                json.dumps(
                    {
                        "status": "blocked",
                        "reasons": ["review package override exceeds approved limit"],
                    }
                )
            )
            return ExitCode.POLICY_BLOCKED
        adapters = {
            "claude": ClaudeAdapter(command=review_policy.provider_commands["claude"], repository_root=ROOT),
            "gemini": GeminiAdapter(command=review_policy.provider_commands["gemini"], repository_root=ROOT),
            "codex": CodexAdapter(command=review_policy.provider_commands["codex"], repository_root=ROOT),
        }
        try:
            package = load_package(args.package, root=ROOT) if args.package else None
            reviewer = args.reviewer_provider
            if reviewer is None and package is not None:
                reviewer = package.manifest.reviewer_provider
            if reviewer is None:
                reviewer = next(
                    (
                        name
                        for name in review_policy.provider_order
                        if name != args.author_provider
                    ),
                    None,
                )
                if reviewer is None:
                    raise ProviderPolicyError(
                        "no independent reviewer is configured"
                    )
            if reviewer not in review_policy.provider_order:
                raise ProviderPolicyError("reviewer is not approved by config")
            requirements = (
                read_review_requirements(
                    ROOT, args.requirements, max_bytes=max_package_bytes
                )
                if args.requirements
                else "Review the manifest-bound change for correctness, security, tests, and architecture."
            )
            verification = collect_fresh_verification_evidence(
                ROOT,
                tuple(command_id.replace("_", ".") for command_id in MERGE_COMMANDS),
            )
            request = ReviewPackageRequest(
                root=ROOT,
                base=trusted_base,
                head=trusted_head,
                author_provider=args.author_provider,
                reviewer_provider=reviewer,
                context_paths=tuple(args.context),
                requirements=requirements,
                verification=verification,
                max_package_bytes=max_package_bytes,
                max_estimated_tokens=max_estimated_tokens,
            )
            orchestrator = ReviewOrchestrator(adapters)
            if package is not None:
                result = orchestrator.run_package(
                    package,
                    request,
                    approved_manifest_sha256=args.approve_manifest,
                )
            else:
                result = orchestrator.run(
                    request, approved_manifest_sha256=args.approve_manifest
                )
        except (
            GovernanceBaseError,
            ReviewPackageBlocked,
            ProviderPolicyError,
            ValueError,
        ) as exc:
            print(json.dumps({"status": "blocked", "reasons": [str(exc)]}))
            return ExitCode.POLICY_BLOCKED
        diagnostic = None
        audit_path = result.package_path / "audit.jsonl"
        if result.status != "completed" and audit_path.is_file():
            try:
                audit_payload = json.loads(audit_path.read_text(encoding="utf-8"))
                diagnostic = {
                    "error": audit_payload.get("error"),
                    "exit_code": audit_payload.get("exit_code"),
                }
            except (OSError, json.JSONDecodeError):
                pass
        print(
            json.dumps(
                {
                    "status": result.status,
                    "verdict": result.verdict,
                    "provider": result.provider,
                    "package_path": str(result.package_path),
                    "manifest_sha256": result.manifest_sha256,
                    "diagnostic": diagnostic,
                    "context": {
                        **package_usage(load_package(result.package_path, root=ROOT)),
                        "profile": args.profile,
                        "estimator": ESTIMATOR,
                        "estimated_token_budget": max_estimated_tokens,
                    },
                },
                sort_keys=True,
            )
        )
        if result.status == "completed":
            return ExitCode.OK if result.verdict == "pass" else ExitCode.POLICY_BLOCKED
        return ExitCode.REVIEW_PENDING
    if args.command == "adjudicate":
        try:
            package = load_package(args.package, root=ROOT)
            decisions_path = resolve_inside(ROOT, args.file)
            if not decisions_path.is_file() or decisions_path.is_symlink():
                raise ValueError("adjudication file must be a regular file inside the repository")
            findings_bytes = (package.path / "findings.json").read_bytes()
            findings_payload = json.loads(findings_bytes)
            decisions_payload = json.loads(decisions_path.read_text(encoding="utf-8"))
            if (
                not isinstance(findings_payload, dict)
                or not isinstance(findings_payload.get("findings"), list)
                or not isinstance(decisions_payload, dict)
                or not isinstance(decisions_payload.get("decisions"), list)
            ):
                raise ValueError("invalid findings or adjudication decision document")
            decisions, blocking = adjudicate_findings(
                findings_payload["findings"],
                decisions_payload["decisions"],
                root=ROOT,
            )
            artifact = {
                "status": "blocked" if blocking else "passed",
                "head_sha": package.manifest.head_sha,
                "manifest_sha256": package.manifest_sha256,
                "findings_sha256": sha256(findings_bytes).hexdigest(),
                "package_path": package.path.resolve().relative_to(ROOT.resolve()).as_posix(),
                "decisions": decisions,
                "blocking_ids": list(blocking),
            }
            atomic_write(
                ROOT / ".agent/.runs/adjudication.json",
                json.dumps(artifact, sort_keys=True) + "\n",
            )
        except (OSError, json.JSONDecodeError, ValueError, PathPolicyError, ReviewPackageBlocked) as exc:
            print(json.dumps({"status": "blocked", "reasons": [str(exc)]}))
            return ExitCode.POLICY_BLOCKED
        print(json.dumps(artifact, sort_keys=True))
        return ExitCode.OK if not blocking else ExitCode.POLICY_BLOCKED
    parser.print_help()
    return ExitCode.OK
