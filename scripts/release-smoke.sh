#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)

run_check() {
  name=$1
  shift
  if "$@"; then
    echo "PASS $name"
  else
    code=$?
    echo "FAIL $name (exit $code)" >&2
    return "$code"
  fi
}

if [ "${1-}" != "--in-place" ]; then
  if ! git -C "$ROOT" rev-parse --verify HEAD >/dev/null 2>&1; then
    echo "release smoke requires a Git HEAD" >&2
    exit 2
  fi
  SMOKE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/agent-release-smoke.XXXXXX")
  cleanup() {
    rm -rf -- "$SMOKE_DIR"
  }
  trap cleanup EXIT HUP INT TERM
  git -C "$ROOT" archive --format=tar HEAD | tar -xf - -C "$SMOKE_DIR"
  AGENT_RELEASE_SMOKE_INNER=1 PYTHONDONTWRITEBYTECODE=1 \
    bash "$SMOKE_DIR/scripts/release-smoke.sh" --in-place
  HEAD_SHA=$(git -C "$ROOT" rev-parse HEAD)
  "$ROOT/scripts/agent" release record-clean-smoke --head "$HEAD_SHA"
  exit 0
fi

cd "$ROOT"
run_check doctor ./scripts/agent doctor --ci
run_check unit-tests env AGENT_RELEASE_SMOKE_INNER=1 PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=.agent/runtime python3 -m unittest discover -s .agent/tests -v
run_check adapters ./scripts/agent adapters check
run_check docs ./scripts/agent docs check
run_check memory ./scripts/agent memory doctor --json
run_check skills ./scripts/agent skills check
run_check licenses ./scripts/agent licenses audit --json

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  run_check tracked-text git diff --check
else
  git init -q
  git add .
  run_check tracked-text git diff --cached --check
fi
