from __future__ import annotations

import sys
from pathlib import Path


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from agent_cli.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
