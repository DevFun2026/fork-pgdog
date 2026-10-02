"""Explicit owner exception for the first 0.1.0 release; not SSH clearance."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

from artifacts.release_receipt import canonical, unique_object

REPOSITORY = "DevFun2026/fork-pgdog"
SOURCE = "09026eec63e0cb2da60389ef623e56ff1e4ba74b"
SOURCE_BASE = "135b4f471761d006a52ce689fa4ed0aee60b73ae"
SOURCE_MANIFEST = "3f2f2acd47069382f05e62ac5feb67728cb5fe9ba7346cf89da05f192a55660f"
OWNER_ID = 107181711
OWNER = "simonle251289"
COMMENT_ID = 5948092075
COMMENT_BODY = "> Tôi duyệt dùng GitHub owner approval và environment packages thay chữ ký SSH cho lần phát hành đầu: image 0.1.0, Helm chart 0.1.0. Giữ nguyên review, CI, scanner và kiểm tra artifact."
AUTHORIZATION = {"method": "github-owner-first-release-exception", "comment_id": COMMENT_ID,
                 "actor_id": OWNER_ID, "actor_login": OWNER,
                 "comment_body_sha256": hashlib.sha256(COMMENT_BODY.encode()).hexdigest(),
                 "security_profile": "standard", "ssh_clearance": "waived-by-owner",
                 "canonical_release_gate": "not-claimed"}
FIELDS = {"schema_version", "repository", "source_sha", "workflow_sha", "image_version", "chart_version", "created_at", "authorization", "reviews", "ci_runs", "evidence_sha256"}
REVIEW_FIELDS = {"status", "verdict", "author_provider", "reviewer_provider", "head_sha", "base_sha", "diff_sha256", "manifest_sha256", "findings_sha256"}
EVIDENCE = {"source-review-audit", "workflow-review-audit", "security-assessment", "threat-model", "release-notes", "migration-rollback", "residual-risks"}
QUALITY = ".github/workflows/fork-quality.yml"
ARTIFACTS = ".github/workflows/artifact-quality.yml"
REQUIRED_JOBS = {QUALITY: {"verification", "scanners (dependency)", "scanners (license)", "scanners (sast)"},
                 ARTIFACTS: {"build (ubuntu-24.04, amd64)", "build (ubuntu-24.04-arm, arm64)"}}


def _hash(value, length):
    return isinstance(value, str) and bool(re.fullmatch(rf"[0-9a-f]{{{length}}}", value))


def parse_initial_receipt(payload, source_sha):
    if not isinstance(payload, dict) or set(payload) != FIELDS or type(payload.get("schema_version")) is not int or payload["schema_version"] != 2:
        raise ValueError("Invalid first-release receipt schema")
    if payload["repository"] != REPOSITORY or payload["source_sha"] != source_sha or source_sha != SOURCE:
        raise ValueError("First-release exception is restricted to the approved PR #7 source")
    workflow = payload["workflow_sha"]
    if not _hash(workflow, 40) or workflow == SOURCE or payload["image_version"] != "0.1.0" or payload["chart_version"] != "0.1.0":
        raise ValueError("First-release workflow/source/versions differ from approval")
    if canonical(payload["authorization"]) != canonical(AUTHORIZATION):
        raise ValueError("First-release owner authorization differs from approval")
    try:
        created = datetime.fromisoformat(payload["created_at"].replace("Z", "+00:00"))
        if created.utcoffset() is None or created > datetime.now(timezone.utc):
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Invalid receipt UTC timestamp") from None
    reviews = payload["reviews"]
    if not isinstance(reviews, dict) or set(reviews) != {"source", "workflow"}:
        raise ValueError("Both artifact-source and publication-workflow reviews are required")
    for role, head, base in (("source", SOURCE, SOURCE_BASE), ("workflow", workflow, SOURCE)):
        review = reviews[role]
        if (not isinstance(review, dict) or set(review) != REVIEW_FIELDS
                or review["status"] != "passed" or review["verdict"] != "pass"
                or review["author_provider"] != "codex" or review["reviewer_provider"] != "gemini"
                or review["head_sha"] != head or review["base_sha"] != base
                or any(not _hash(review[key], 64) for key in ("diff_sha256", "manifest_sha256", "findings_sha256"))):
            raise ValueError("Invalid independent first-release review binding")
    if reviews["source"]["manifest_sha256"] != SOURCE_MANIFEST:
        raise ValueError("Historical source review does not match the approved manifest")
    expected = {"source-quality": (SOURCE, QUALITY, 36960858752), "source-artifacts": (SOURCE, ARTIFACTS, 36961300035),
                "workflow-quality": (workflow, QUALITY, None), "workflow-artifacts": (workflow, ARTIFACTS, None)}
    runs = payload["ci_runs"]
    if not isinstance(runs, list) or len(runs) != len(expected):
        raise ValueError("Four real source/workflow quality and native CI witnesses are required")
    seen = set()
    ids = set()
    for run in runs:
        if not isinstance(run, dict) or set(run) != {"role", "id", "attempt", "head_sha", "path"} or run["role"] not in expected or run["role"] in seen:
            raise ValueError("Invalid/duplicate CI witness role")
        head, path, pinned_id = expected[run["role"]]
        if (type(run["id"]) is not int or run["id"] <= 0 or run["id"] in ids
                or type(run["attempt"]) is not int or run["attempt"] <= 0
                or run["head_sha"] != head or run["path"] != path
                or (pinned_id is not None and run["id"] != pinned_id)):
            raise ValueError("CI witness does not match approved source/workflow")
        seen.add(run["role"]); ids.add(run["id"])
    evidence = payload["evidence_sha256"]
    if not isinstance(evidence, dict) or set(evidence) != EVIDENCE or any(not _hash(value, 64) for value in evidence.values()):
        raise ValueError("Missing first-release review/security/document hashes")
    return payload


def github_api(endpoint):
    # Credentials stay in gh's normal environment/keyring, never argv or errors.
    try:
        result = subprocess.run(["gh", "api", "--hostname", "github.com", "--method", "GET", endpoint], text=True, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("Authenticated GitHub evidence could not be verified") from None
    if result.returncode:
        raise ValueError("Authenticated GitHub evidence could not be verified")
    try:
        value = json.loads(result.stdout, object_pairs_hook=unique_object)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, TypeError):
        raise ValueError("Malformed GitHub evidence") from None


def validate_live(receipt, *, actor_id, workflow_sha, api=None):
    parse_initial_receipt(receipt, SOURCE)
    if actor_id != str(OWNER_ID) or workflow_sha != receipt["workflow_sha"]:
        raise ValueError("Only the approved owner can dispatch the reviewed main workflow")
    api = api or github_api
    prefix = "repos/" + REPOSITORY + "/"
    comment = api(prefix + f"issues/comments/{COMMENT_ID}")
    if (comment.get("id") != COMMENT_ID or comment.get("user", {}).get("id") != OWNER_ID
            or comment.get("user", {}).get("login") != OWNER or comment.get("body") != COMMENT_BODY):
        raise ValueError("Owner comment was changed, removed or does not match approval")
    permission = api(prefix + f"collaborators/{OWNER}/permission")
    if permission.get("permission") != "admin" or permission.get("user", {}).get("id") != OWNER_ID:
        raise ValueError("Approved owner no longer has repository administration permission")
    environment = api(prefix + "environments/packages")
    reviewers = [reviewer for rule in environment.get("protection_rules", []) if rule.get("type") == "required_reviewers" for reviewer in rule.get("reviewers", [])]
    if not any(row.get("type") == "User" and row.get("reviewer", {}).get("id") == OWNER_ID for row in reviewers):
        raise ValueError("packages environment no longer requires the approved owner")
    if environment.get("deployment_branch_policy") != {"protected_branches": False, "custom_branch_policies": True}:
        raise ValueError("packages environment must restrict deployment to main")
    branches = api(prefix + "environments/packages/deployment-branch-policies")
    if branches.get("total_count") != 1 or [(row.get("name"), row.get("type")) for row in branches.get("branch_policies", [])] != [("main", "branch")]:
        raise ValueError("packages deployment branch policy differs from main-only approval")
    for witness in receipt["ci_runs"]:
        run = api(prefix + f"actions/runs/{witness['id']}")
        if (run.get("id") != witness["id"] or run.get("head_sha") != witness["head_sha"]
                or run.get("path") != witness["path"] or run.get("run_attempt") != witness["attempt"]
                or run.get("status") != "completed" or run.get("conclusion") != "success"):
            raise ValueError("CI witness failed, changed attempt or differs from reviewed source")
        jobs = api(prefix + f"actions/runs/{witness['id']}/attempts/{witness['attempt']}/jobs?per_page=100")
        rows = jobs.get("jobs")
        if not isinstance(rows, list) or jobs.get("total_count") != len(rows) or len(rows) > 100:
            raise ValueError("Incomplete CI job evidence")
        expected = REQUIRED_JOBS[witness["path"]]
        by_name = {row.get("name"): row for row in rows}
        if len(by_name) != len(rows) or not expected.issubset(by_name) or any(by_name[name].get("status") != "completed" or by_name[name].get("conclusion") != "success" for name in expected):
            raise ValueError("Required native/scanner/full-suite job is missing, skipped or unsuccessful")


def _git(root, *args):
    return subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=True).stdout


def review_metadata(root, package_path, head, base):
    package = package_path.resolve(strict=True)
    runs = (root / ".agent/.runs").resolve()
    if package.parent != runs or not package.name.startswith("review-") or package_path.is_symlink():
        raise ValueError("Review must be an immutable local .agent/.runs package")
    def read(name):
        path = package / name
        if not path.is_file() or path.is_symlink(): raise ValueError("Missing or unsafe review evidence")
        try: path.resolve().relative_to(package)
        except ValueError: raise ValueError("Review evidence escapes immutable package") from None
        return path.read_bytes()
    manifest_bytes = read("manifest.json")
    manifest = json.loads(manifest_bytes, object_pairs_hook=unique_object)
    findings_bytes = read("findings.json")
    findings = json.loads(findings_bytes, object_pairs_hook=unique_object)
    audit = json.loads(read("audit.jsonl"), object_pairs_hook=unique_object)
    manifest_sha = hashlib.sha256(canonical(manifest)).hexdigest()
    diff = _git(root, "diff", "--binary", base, head).encode()
    diff_sha = hashlib.sha256(diff).hexdigest()
    if (manifest.get("head_sha") != head or manifest.get("base_sha") != base
            or manifest.get("author_provider") != "codex" or manifest.get("reviewer_provider") != "gemini"
            or manifest.get("full_diff_sha256", manifest.get("diff_sha256")) != diff_sha
            or hashlib.sha256(read("diff.patch")).hexdigest() != manifest.get("diff_sha256")
            or audit.get("manifest_sha256") != manifest_sha or audit.get("status") != "completed"
            or audit.get("provider") != "gemini" or audit.get("verdict") != "pass" or audit.get("exit_code") != 0
            or not _hash(audit.get("stdout_sha256"), 64) or findings != {"verdict": "pass", "findings": []}):
        raise ValueError("Independent review is missing, failed or does not match the real Git change")
    for name, field in (("requirements.md", "requirements_sha256"), ("verification.json", "verification_sha256"), ("policy.md", "policy_sha256"), ("review-schema.json", "schema_sha256")):
        if hashlib.sha256(read(name)).hexdigest() != manifest.get(field):
            raise ValueError("Review package metadata differs from reviewed manifest")
    scope = sorted(_git(root, "diff", "--name-only", base, head).splitlines())
    if scope != manifest.get("scope"):
        raise ValueError("Review scope differs from the real Git change")
    for entry in manifest.get("files", []):
        relative = Path(entry["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Unsafe context path")
        data = read("context/" + entry["path"])
        if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("Review context changed")
    return {"status": "passed", "verdict": "pass", "author_provider": "codex", "reviewer_provider": "gemini", "head_sha": head, "base_sha": base,
            "diff_sha256": diff_sha, "manifest_sha256": manifest_sha, "findings_sha256": hashlib.sha256(findings_bytes).hexdigest()}, hashlib.sha256(read("audit.jsonl")).hexdigest()


def create_initial_receipt(root, output, source_review, workflow_review, quality_run, artifact_run):
    root = root.resolve()
    if output.exists() or output.is_symlink():
        raise ValueError("Existing receipt must be preserved; choose a new output path")
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all").strip():
        raise ValueError("Receipt requires a clean committed workflow candidate")
    workflow = _git(root, "rev-parse", "HEAD").strip()
    _git(root, "merge-base", "--is-ancestor", SOURCE, workflow)
    source_metadata, source_audit = review_metadata(root, source_review, SOURCE, SOURCE_BASE)
    workflow_metadata, workflow_audit = review_metadata(root, workflow_review, workflow, SOURCE)
    api = github_api
    witnesses = []
    for role, number, head, path in (("source-quality", 36960858752, SOURCE, QUALITY), ("source-artifacts", 36961300035, SOURCE, ARTIFACTS), ("workflow-quality", quality_run, workflow, QUALITY), ("workflow-artifacts", artifact_run, workflow, ARTIFACTS)):
        run = api(f"repos/{REPOSITORY}/actions/runs/{number}")
        witnesses.append({"role": role, "id": number, "attempt": run.get("run_attempt"), "head_sha": head, "path": path})
    documents = {"threat-model": "docs/security/threat-model.md", "release-notes": "docs/releases/fork-artifacts.md", "migration-rollback": "docs/operations/fork-artifact-rollback.md", "residual-risks": "docs/security/residual-risks.md"}
    evidence = {key: hashlib.sha256((root / path).read_bytes()).hexdigest() for key, path in documents.items()}
    assessment_path = root / ".agent/.runs/artifacts/fork-image-helm-handoff/security-assessment-09026eec.json"
    assessment_record = json.loads(assessment_path.read_text(), object_pairs_hook=unique_object)
    assessment = assessment_record.get("assessment", {})
    source_scope = sorted(_git(root, "diff", "--name-only", SOURCE_BASE, SOURCE).splitlines())
    if (assessment.get("head_sha") != SOURCE or assessment.get("base_sha") != SOURCE_BASE
            or assessment.get("approved_profile") != "standard" or assessment.get("assessed_profile") != "standard"
            or assessment.get("diff_sha256") != source_metadata["diff_sha256"]
            or assessment.get("reviewed_scope") != source_scope):
        raise ValueError("Original Standard security assessment is missing or does not match source")
    evidence.update({"source-review-audit": source_audit, "workflow-review-audit": workflow_audit, "security-assessment": hashlib.sha256(assessment_path.read_bytes()).hexdigest()})
    receipt = {"schema_version": 2, "repository": REPOSITORY, "source_sha": SOURCE, "workflow_sha": workflow, "image_version": "0.1.0", "chart_version": "0.1.0",
               "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "authorization": dict(AUTHORIZATION),
               "reviews": {"source": source_metadata, "workflow": workflow_metadata}, "ci_runs": witnesses, "evidence_sha256": evidence}
    user = api("user")
    validate_live(receipt, actor_id=str(user.get("id")), workflow_sha=workflow, api=api)
    if _git(root, "rev-parse", "HEAD").strip() != workflow or _git(root, "status", "--porcelain=v1", "--untracked-files=all").strip():
        raise ValueError("Workflow candidate changed during receipt creation")
    raw = canonical(receipt)
    if len(raw) > 32768: raise ValueError("Receipt exceeds 32 KiB")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(raw + b"\n")
    return hashlib.sha256(raw).hexdigest()
