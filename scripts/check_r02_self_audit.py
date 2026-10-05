#!/usr/bin/env python3
"""CI guard: the anti-hallucination rule must pass on its own source tree.

Reads a ``cits-lint --rules R02 --format json`` report and fails when the tool
reports a finding against the packaged source. A linter that fails on its own
repository gets switched off, so this is enforced rather than merely intended.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check_r02_self_audit.py <report.json>", file=sys.stderr)
        return 2

    report = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    errors = report.get("error_count", 0)
    if errors == 0:
        print("R02 self-audit clean")
        return 0

    print(f"R02 self-audit found {errors} finding(s):", file=sys.stderr)
    for v in report.get("violations", []):
        location = f"{v.get('file_path')}:{v.get('line_number')}"
        print(f"  {location} {v.get('message')}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
