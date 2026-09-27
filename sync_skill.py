#!/usr/bin/env python3
"""Multi-Agent Skill Synchronizer & Deployment Tool for C-ITS Expert.

Mirrors the cits-expert skill into global and project-level directories for:
- Antigravity / Gemini CLI Plugins (~/.gemini/config/plugins/cits-expert & cits-asn1)
- Universal Agent Directory (~/.agents/skills/cits-expert)
- Claude Code (~/.claude/skills/cits-expert)
- Project-specific directories (.agents/skills/cits-expert)
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


class SkillSynchronizer:
    def __init__(self, home_dir: Path | None = None, repo_root: Path | None = None) -> None:
        self.home_dir = home_dir or Path.home()
        self.repo_root = repo_root or Path(__file__).resolve().parent
        self.source_skill_dir = self.repo_root / "skill" / "cits-expert"

    def get_global_targets(self) -> list[Path]:
        """Returns the list of canonical agent skill locations."""
        return [
            # Antigravity new plugin
            self.home_dir / ".gemini" / "config" / "plugins" / "cits-expert" / "skills" / "cits-expert",
            # Antigravity existing cits-asn1 drop-in update
            self.home_dir / ".gemini" / "config" / "plugins" / "cits-asn1" / "skills" / "cits-asn1",
            # Universal Agent / Codex / OpenCode directory
            self.home_dir / ".agents" / "skills" / "cits-expert",
            # Claude Code directory
            self.home_dir / ".claude" / "skills" / "cits-expert",
        ]

    def sync_to_directory(self, target_dir: Path, dry_run: bool = False) -> None:
        """Copies SKILL.md, references, and examples to target directory."""
        if not self.source_skill_dir.exists():
            raise FileNotFoundError(f"Source skill directory not found at {self.source_skill_dir}")

        if dry_run:
            print(f"[DRY-RUN] Would sync {self.source_skill_dir} -> {target_dir}")
            return

        target_dir.mkdir(parents=True, exist_ok=True)

        # 1. Copy SKILL.md
        shutil.copy2(self.source_skill_dir / "SKILL.md", target_dir / "SKILL.md")

        # 2. Copy references/
        src_refs = self.source_skill_dir / "references"
        dst_refs = target_dir / "references"
        if src_refs.exists():
            if dst_refs.exists():
                shutil.rmtree(dst_refs)
            shutil.copytree(src_refs, dst_refs)

        # 3. Copy examples/
        src_examples = self.source_skill_dir / "examples"
        dst_examples = target_dir / "examples"
        if src_examples.exists():
            if dst_examples.exists():
                shutil.rmtree(dst_examples)
            shutil.copytree(src_examples, dst_examples)

        print(f"[OK] Synced {self.source_skill_dir.name} -> {target_dir}")

    def sync_all_global(self, dry_run: bool = False) -> None:
        for target in self.get_global_targets():
            self.sync_to_directory(target, dry_run=dry_run)


def main() -> int:
    parser = argparse.ArgumentParser(description="Synchronize C-ITS Expert skill across agent runtimes.")
    parser.add_argument("--install-global", action="store_true", help="Install into all global agent locations.")
    parser.add_argument("--install-project", type=Path, help="Install into target project (.agents/skills/cits-expert).")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without modifying files.")

    args = parser.parse_args()
    syncer = SkillSynchronizer()

    if not args.install_global and not args.install_project:
        parser.print_help()
        return 1

    if args.install_global:
        syncer.sync_all_global(dry_run=args.dry_run)

    if args.install_project:
        target = args.install_project / ".agents" / "skills" / "cits-expert"
        syncer.sync_to_directory(target, dry_run=args.dry_run)

    return 0


if __name__ == "__main__":
    sys.exit(main())
