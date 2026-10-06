#!/usr/bin/env python3
"""Print only public test identifiers and fixed phase labels, never raw test logs."""
import json
from pathlib import Path
import re
import subprocess

FATAL_PHASES = frozenset({"pgdog-build", "legacy-start", "legacy-ready"})


def summarize(log: str, public_names: set[str]) -> dict[str, list[str]]:
    failed = set()
    phases = set()
    for line in re.sub(r"\x1b\[[0-9;]*m", "", log).splitlines():
        match = re.fullmatch(r"\s*(?:FAIL|TIMEOUT|LEAK)\s+\[[^\]]+\]\s+[\w:/.-]+\s+([\w:.-]+)\s*", line)
        if match:
            name = match[1].rsplit("::", 1)[-1]
            if name in public_names:
                failed.add(name)
        match = re.match(r"^(?:FAIL|ERROR): (test_\w+) \(", line)
        if match and match[1] in public_names:
            failed.add(match[1])
        match = re.fullmatch(r"\s*test\s+([\w:.-]+)\s+\.\.\.\s+FAILED\s*", line)
        if match:
            name = match[1].rsplit("::", 1)[-1]
            if name in public_names:
                failed.add(name)
        match = re.fullmatch(r"FATAL_PHASE: ([a-z-]+)", line)
        if match and match[1] in FATAL_PHASES:
            phases.add(match[1])
        if line.startswith("FAILED ("):
            if re.match(r"FAILED \(\d+\): bash ../../scripts/strict-read-tests\.sh(?:\s|$)", line):
                phase = re.search(r"(?:^|\s)--phase\s+(baseline|protocol|core|all)(?:\s|$)", line)
                phases.add(f"strict-read-{phase[1]}" if phase else "strict-read")
            elif ": cargo nextest run " in line:
                phases.add("rust-integration" if "--profile integration" in line else "rust-unit")
            elif ": cargo test " in line:
                phases.add("rust-doc")
            elif "python3 -m unittest " in line:
                phases.add("agent-unit")
            elif "./scripts/agent " in line:
                phases.add("agent-checks")
    return {"failed_tests": sorted(failed), "failed_phases": sorted(phases)}


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    names = set()
    # Identifiers must occur in tracked public source; never echo arbitrary log text.
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
    for relative in tracked:
        path = root / relative
        if path.suffix in {".rs", ".py"} and path.is_file():
            names.update(re.findall(r"\b(?:fn|def)\s+([A-Za-z_]\w*)\s*\(", path.read_text(errors="replace")))
    log = root / ".agent/.runs/gate-logs/full-tests.log"
    result = summarize(log.read_text(errors="replace"), names) if log.is_file() else {"log_available": False}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
