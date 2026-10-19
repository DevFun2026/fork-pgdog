"""Strict schema-3 receipt validation for an owner-reviewed GitHub release."""
import hashlib
import re
from datetime import datetime, timedelta, timezone

import tomllib

from artifacts.owner_approval import REQUIRED_JOBS, github_api
from artifacts.release_receipt import canonical, validate_version

REPOSITORY = "DevFun2026/fork-pgdog"
OWNER_ID = 107181711
OWNER = "simonle251289"
METHOD = "github-owner-reviewed-release"
# Gemini (AGY) is the independent reviewer, so it can never be the author.
AUTHOR_PROVIDERS = frozenset({"claude", "codex"})
REVIEWER_PROVIDER = "gemini"
REVIEW_FIELDS = {
    "status", "verdict", "author_provider", "reviewer_provider", "head_sha",
    "base_sha", "diff_sha256", "manifest_sha256", "findings_sha256",
    "partitioned", "audit_sha256",
}
RECEIPT_FIELDS = {
    "schema_version", "repository", "source_sha", "workflow_sha", "image_version",
    "chart_version", "created_at", "authorization", "provenance", "reviews",
    "ci_runs", "evidence_sha256",
}
AUTHORIZATION_FIELDS = {
    "method", "actor_id", "actor_login", "comment_id", "comment_body_sha256",
    "security_profile", "ssh_clearance", "canonical_release_gate",
}
EVIDENCE_FIELDS = {
    "source-review-audit", "workflow-review-audit", "source-security-assessment",
    "workflow-security-assessment", "threat-model", "release-notes",
    "migration-rollback", "residual-risks",
}
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z")
CI_ROLES = {
    "source-quality": ".github/workflows/fork-quality.yml",
    "source-artifacts": ".github/workflows/artifact-quality.yml",
    "workflow-quality": ".github/workflows/fork-quality.yml",
    "workflow-artifacts": ".github/workflows/artifact-quality.yml",
}


def _is_int(value):
    return type(value) is int


def _is_sha(value):
    return isinstance(value, str) and SHA_RE.fullmatch(value) is not None


def _is_hash(value):
    return isinstance(value, str) and HASH_RE.fullmatch(value) is not None


def _timestamp(value):
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        raise ValueError("Invalid receipt UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() != timedelta(0) or parsed > datetime.now(timezone.utc):
            raise ValueError()
    except (ValueError, TypeError, OverflowError):
        raise ValueError("Invalid UTC timestamp") from None


def _approval_payload(receipt):
    payload = {key: value for key, value in receipt.items()}
    authorization = dict(payload["authorization"])
    authorization.pop("comment_id", None)
    authorization.pop("comment_body_sha256", None)
    payload["authorization"] = authorization
    return payload


def approval_body(receipt):
    """Return the exact owner comment, bound to the non-circular payload."""
    if not isinstance(receipt, dict):
        raise ValueError("Invalid owner approval payload")  # noqa: TRY004 -- malformed receipt is a validation failure
    digest = hashlib.sha256(canonical(_approval_payload(receipt))).hexdigest()
    return (
        f"Approve release for {REPOSITORY}\n"
        f"Image: {receipt['image_version']}\n"
        f"Helm chart: {receipt['chart_version']}\n"
        f"Source commit: {receipt['source_sha']}\n"
        f"Workflow commit: {receipt['workflow_sha']}\n"
        "Security profile: standard\n"
        "SSH clearance: waived by owner\n"
        "Canonical release gate: not claimed\n\n"
        f"Approval payload SHA256: {digest}\n"
    )


def parse_owner_receipt(payload, source_sha, allow_unapproved=False):
    """Validate the complete schema-3 receipt without consulting live state."""
    if not isinstance(payload, dict) or set(payload) != RECEIPT_FIELDS:
        raise ValueError("Unexpected owner release receipt fields")
    if not _is_int(payload.get("schema_version")) or payload["schema_version"] != 3:
        raise ValueError("Unsupported owner release receipt schema")
    if payload["repository"] != REPOSITORY:
        raise ValueError("Owner release receipt is for another repository")
    if not _is_sha(source_sha) or not _is_sha(payload["source_sha"]) or payload["source_sha"] != source_sha:
        raise ValueError("Receipt source differs from selected source merge SHA")
    if not _is_sha(payload["workflow_sha"]) or payload["workflow_sha"] == payload["source_sha"]:
        raise ValueError("Invalid workflow merge SHA")
    try:
        validate_version(payload["image_version"])
        validate_version(payload["chart_version"])
    except (ValueError, TypeError):
        raise ValueError("Invalid release image/chart SemVer") from None
    _timestamp(payload["created_at"])

    authorization = payload["authorization"]
    if not isinstance(authorization, dict) or set(authorization) != AUTHORIZATION_FIELDS:
        raise ValueError("Invalid owner authorization fields")
    comment_id = authorization["comment_id"]
    draft = _is_int(comment_id) and comment_id == 0
    if (authorization["method"] != METHOD or not _is_int(authorization["actor_id"])
            or authorization["actor_id"] != OWNER_ID or authorization["actor_login"] != OWNER
            or not _is_int(comment_id) or comment_id < 0
            or authorization["security_profile"] != "standard"
            or authorization["ssh_clearance"] != "waived-by-owner"
            or authorization["canonical_release_gate"] != "not-claimed"
            or not _is_hash(authorization["comment_body_sha256"])):
        raise ValueError("Owner authorization identity or mode differs from approval")
    if draft and not allow_unapproved:
        raise ValueError("Draft owner receipt has no positive approval comment")
    expected_body_hash = hashlib.sha256(approval_body(payload).encode("utf-8")).hexdigest()
    if authorization["comment_body_sha256"] != expected_body_hash:
        raise ValueError("Owner approval payload/body hash mismatch")

    provenance = payload["provenance"]
    if (not isinstance(provenance, dict) or set(provenance) != {"source_pr", "workflow_pr"}
            or any(not _is_int(provenance[key]) or provenance[key] <= 0 for key in ("source_pr", "workflow_pr"))
            or provenance["source_pr"] == provenance["workflow_pr"]):
        raise ValueError("Invalid source/workflow PR provenance")

    reviews = payload["reviews"]
    if not isinstance(reviews, dict) or set(reviews) != {"source", "workflow"}:
        raise ValueError("Both original source and workflow reviews are required")
    for role in ("source", "workflow"):
        review = reviews[role]
        if (not isinstance(review, dict) or set(review) != REVIEW_FIELDS
                or review["status"] != "passed" or review["verdict"] != "pass"
                or review["author_provider"] not in AUTHOR_PROVIDERS or review["reviewer_provider"] != REVIEWER_PROVIDER
                or not _is_sha(review["head_sha"]) or not _is_sha(review["base_sha"])
                or any(not _is_hash(review[key]) for key in ("diff_sha256", "manifest_sha256", "findings_sha256", "audit_sha256"))
                or type(review["partitioned"]) is not bool):
            raise ValueError("Invalid original independent review binding")
        if review["head_sha"] == review["base_sha"]:
            raise ValueError("Review head and base must be distinct")

    expected_ci = {
        "source-quality": reviews["source"]["head_sha"],
        "source-artifacts": reviews["source"]["head_sha"],
        "workflow-quality": reviews["workflow"]["head_sha"],
        "workflow-artifacts": reviews["workflow"]["head_sha"],
    }
    runs = payload["ci_runs"]
    if not isinstance(runs, list) or len(runs) != len(CI_ROLES):
        raise ValueError("Four source/workflow CI witnesses are required")
    seen_roles, seen_ids = set(), set()
    for witness in runs:
        fields = {"role", "id", "attempt", "head_sha", "path"}
        if not isinstance(witness, dict) or set(witness) != fields:
            raise ValueError("Invalid CI witness fields")
        role = witness["role"]
        if not isinstance(role, str) or role not in CI_ROLES or role in seen_roles:
            raise ValueError("Invalid or duplicate CI witness role")
        if (not _is_int(witness["id"]) or witness["id"] <= 0 or witness["id"] in seen_ids
                or not _is_int(witness["attempt"]) or witness["attempt"] <= 0
                or witness["head_sha"] != expected_ci[role] or not _is_sha(witness["head_sha"])
                or witness["path"] != CI_ROLES[role]):
            raise ValueError("CI witness differs from original reviewed head/workflow")
        seen_roles.add(role)
        seen_ids.add(witness["id"])

    evidence = payload["evidence_sha256"]
    if (not isinstance(evidence, dict) or set(evidence) != EVIDENCE_FIELDS
            or any(not _is_hash(value) for value in evidence.values())):
        raise ValueError("Missing or invalid release evidence hashes")
    if (evidence["source-review-audit"] != reviews["source"]["audit_sha256"]
            or evidence["workflow-review-audit"] != reviews["workflow"]["audit_sha256"]):
        raise ValueError("Review audit hashes differ from the bound review summaries")
    return payload


def _read(api, endpoint):
    value = api(endpoint)
    if not isinstance(value, dict):
        raise ValueError("Malformed live GitHub evidence")  # noqa: TRY004 -- remote evidence fails closed as validation
    return value


def _git(root, *args):
    import subprocess
    try:
        result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("Local Git history could not verify release ancestry") from None
    if result.returncode:
        raise ValueError("Local Git history could not verify release ancestry")
    return result.stdout.strip()


def validate_standard_policy(root, receipt):
    """Require Standard policy in every reviewed and merged committed config."""
    if not isinstance(receipt, dict) or not isinstance(receipt.get("reviews"), dict):
        raise ValueError("Receipt lacks source/workflow review identities for policy validation")  # noqa: TRY004 -- invalid receipt is a validation failure
    reviews = receipt["reviews"]
    if any(not isinstance(reviews.get(role), dict) for role in ("source", "workflow")):
        raise ValueError("Receipt lacks source/workflow review identities for policy validation")
    revisions = (
        reviews.get("source", {}).get("base_sha"),
        reviews.get("source", {}).get("head_sha"),
        receipt.get("source_sha"),
        reviews.get("workflow", {}).get("base_sha"),
        reviews.get("workflow", {}).get("head_sha"),
        receipt.get("workflow_sha"),
    )
    if any(not _is_sha(revision) for revision in revisions):
        raise ValueError("Receipt has invalid commits for Standard policy validation")
    for revision in dict.fromkeys(revisions):
        try:
            if _git(root, "cat-file", "-t", revision) != "commit":
                raise ValueError()
            entry = _git(root, "ls-tree", revision, "--", ".agent/config.toml")
            metadata, separator, path = entry.partition("\t")
            mode, kind, blob_sha = metadata.split()
            if (not separator or path != ".agent/config.toml" or mode not in {"100644", "100755"}
                    or kind != "blob" or not _is_sha(blob_sha)):
                raise ValueError()
            committed_config = _git(root, "cat-file", "blob", blob_sha)
            config = tomllib.loads(committed_config)
        except (ValueError, tomllib.TOMLDecodeError, UnicodeDecodeError):
            raise ValueError("Committed .agent/config.toml is missing or malformed") from None
        project = config.get("project")
        if (not isinstance(project, dict) or type(project.get("security_profile")) is not str
                or project["security_profile"] != "standard"):
            raise ValueError("Every reviewed and merged commit must retain the Standard security profile")


def _live_commit(api, root, sha):
    live = _read(api, f"repos/{REPOSITORY}/commits/{sha}")
    commit = live.get("commit")
    if not isinstance(commit, dict):
        raise ValueError("Malformed live Git commit evidence")  # noqa: TRY004 -- remote evidence fails closed as validation
    tree = commit.get("tree")
    parents = live.get("parents")
    if (live.get("sha") != sha or not isinstance(tree, dict) or not _is_sha(tree.get("sha"))
            or not isinstance(parents, list) or any(not isinstance(row, dict) or not _is_sha(row.get("sha")) for row in parents)):
        raise ValueError("Malformed live Git commit evidence")
    local_tree = _git(root, "rev-parse", f"{sha}^{{tree}}")
    local_parents = _git(root, "rev-list", "--parents", "-n", "1", sha).split()
    if tree["sha"] != local_tree or local_parents != [sha, *(parent["sha"] for parent in parents)]:
        raise ValueError("Live GitHub commit differs from local source history")
    return tree["sha"], [parent["sha"] for parent in parents]


def _validate_pr(api, number, role, receipt):
    review = receipt["reviews"][role]
    expected_merge = receipt["source_sha"] if role == "source" else receipt["workflow_sha"]
    pr = _read(api, f"repos/{REPOSITORY}/pulls/{number}")
    base, head = pr.get("base"), pr.get("head")
    merged_at = pr.get("merged_at")
    try:
        _timestamp(merged_at)
    except ValueError:
        raise ValueError("Source/workflow PR has no valid merge timestamp") from None
    if (pr.get("number") != number or pr.get("state") != "closed" or pr.get("merged") is not True
            or pr.get("merge_commit_sha") != expected_merge
            or not isinstance(base, dict) or base.get("ref") != "main"
            or base.get("sha") != review["base_sha"]
            or not isinstance(base.get("repo"), dict) or base["repo"].get("full_name") != REPOSITORY
            or not isinstance(head, dict) or head.get("sha") != review["head_sha"]
            or not isinstance(head.get("repo"), dict) or head["repo"].get("full_name") != REPOSITORY):
        raise ValueError("Source/workflow PR is not the expected merged same-repository main PR")
    return review["base_sha"], review["head_sha"], expected_merge


def validate_live(receipt, *, actor_id, workflow_sha, root, api=None):
    """Re-read all owner, PR, Git, main, environment and CI trust anchors."""
    parse_owner_receipt(receipt, receipt.get("source_sha") if isinstance(receipt, dict) else None)
    if (type(actor_id) is not str or actor_id != str(OWNER_ID)
            or not _is_sha(workflow_sha) or workflow_sha != receipt["workflow_sha"]):
        raise ValueError("Only the approved owner may dispatch the reviewed main workflow")
    validate_standard_policy(root, receipt)
    api = api or github_api
    prefix = f"repos/{REPOSITORY}/"

    source_number = receipt["provenance"]["source_pr"]
    workflow_number = receipt["provenance"]["workflow_pr"]
    source_base, source_head, source_merge = _validate_pr(api, source_number, "source", receipt)
    workflow_base, workflow_head, workflow_merge = _validate_pr(api, workflow_number, "workflow", receipt)
    if workflow_base != source_merge:
        raise ValueError("Workflow review must be based on the source merge")

    source_tree, source_parents = _live_commit(api, root, source_merge)
    source_head_tree, _ = _live_commit(api, root, source_head)
    workflow_tree, workflow_parents = _live_commit(api, root, workflow_merge)
    workflow_head_tree, _ = _live_commit(api, root, workflow_head)
    if source_parents != [source_base, source_head] or source_tree != source_head_tree:
        raise ValueError("Source merge commit does not preserve exact reviewed base/head and tree")
    if workflow_parents != [workflow_base, workflow_head] or workflow_tree != workflow_head_tree:
        raise ValueError("Workflow merge commit does not preserve exact reviewed base/head and tree")
    _git(root, "merge-base", "--is-ancestor", source_merge, workflow_merge)
    if _git(root, "rev-parse", "HEAD") != workflow_sha:
        raise ValueError("Dispatch checkout differs from the reviewed workflow merge")
    main_ref = _read(api, prefix + "git/ref/heads/main")
    if not isinstance(main_ref.get("object"), dict) or main_ref["object"].get("sha") != workflow_sha:
        raise ValueError("Live main no longer equals the reviewed workflow dispatch SHA")

    authorization = receipt["authorization"]
    comment = _read(api, prefix + f"issues/comments/{authorization['comment_id']}")
    expected_issue_url = f"https://api.github.com/repos/{REPOSITORY}/issues/{workflow_number}"
    comment_user = comment.get("user")
    if (comment.get("id") != authorization["comment_id"]
            or not isinstance(comment_user, dict) or comment_user.get("id") != OWNER_ID
            or comment_user.get("login") != OWNER
            or comment.get("issue_url") != expected_issue_url
            or comment.get("body") != approval_body(receipt)
            or hashlib.sha256(comment.get("body", "").encode("utf-8")).hexdigest() != authorization["comment_body_sha256"]):
        raise ValueError("Owner approval comment is missing, changed or belongs to another PR")

    permission = _read(api, prefix + f"collaborators/{OWNER}/permission")
    permission_user = permission.get("user")
    if (permission.get("permission") != "admin"
            or not isinstance(permission_user, dict) or permission_user.get("id") != OWNER_ID
            or permission_user.get("login") != OWNER):
        raise ValueError("Approved owner no longer has repository administration permission")
    environment = _read(api, prefix + "environments/packages")
    rules = environment.get("protection_rules")
    if not isinstance(rules, list):
        raise ValueError("packages environment protection rules are missing")  # noqa: TRY004 -- missing policy is a validation failure
    reviewers = []
    for rule in rules:
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers":
            rows = rule.get("reviewers")
            if isinstance(rows, list):
                reviewers.extend(rows)
    if not any(isinstance(row, dict) and row.get("type") == "User"
               and isinstance(row.get("reviewer"), dict) and row["reviewer"].get("id") == OWNER_ID for row in reviewers):
        raise ValueError("packages environment no longer requires the approved owner")
    if environment.get("deployment_branch_policy") != {"protected_branches": False, "custom_branch_policies": True}:
        raise ValueError("packages environment must restrict deployment to main")
    branches = _read(api, prefix + "environments/packages/deployment-branch-policies")
    rows = branches.get("branch_policies")
    if (not isinstance(rows, list) or type(branches.get("total_count")) is not int
            or branches["total_count"] != 1 or len(rows) != 1
            or not isinstance(rows[0], dict) or rows[0].get("name") != "main" or rows[0].get("type") != "branch"):
        raise ValueError("packages deployment branch policy differs from exact main-only approval")

    for witness in receipt["ci_runs"]:
        run_id, attempt = witness["id"], witness["attempt"]
        run = _read(api, prefix + f"actions/runs/{run_id}")
        if (run.get("id") != run_id or run.get("head_sha") != witness["head_sha"]
                or run.get("path") != witness["path"] or run.get("run_attempt") != attempt
                or run.get("status") != "completed" or run.get("conclusion") != "success"):
            raise ValueError("CI witness failed, changed attempt or differs from the original reviewed head")
        jobs = _read(api, prefix + f"actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
        rows = jobs.get("jobs")
        if (not isinstance(rows, list) or type(jobs.get("total_count")) is not int
                or jobs["total_count"] != len(rows) or len(rows) > 100):
            raise ValueError("Incomplete CI job evidence")
        by_name = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("name"), str) or row["name"] in by_name:
                raise ValueError("Duplicate or malformed CI job evidence")
            by_name[row["name"]] = row
        expected = REQUIRED_JOBS[witness["path"]]
        if (not expected.issubset(by_name)
                or any(by_name[name].get("status") != "completed" or by_name[name].get("conclusion") != "success" for name in expected)):
            raise ValueError("Required native/scanner/full-suite job is missing, skipped or unsuccessful")
