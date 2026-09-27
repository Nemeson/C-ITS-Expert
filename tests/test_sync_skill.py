from pathlib import Path

from sync_skill import SkillSynchronizer


def test_sync_targets_discovery(tmp_path: Path):
    syncer = SkillSynchronizer(home_dir=tmp_path)
    targets = syncer.get_global_targets()

    # Must contain Gemini plugins, .agents/skills, and .claude/skills
    names = [t.name for t in targets]
    assert "cits-expert" in names or "cits-asn1" in names
    paths_str = [str(t) for t in targets]
    assert any(".gemini" in p for p in paths_str)
    assert any(".agents" in p for p in paths_str)
    assert any(".claude" in p for p in paths_str)


def test_sync_copy_to_custom_target(tmp_path: Path):
    dest_dir = tmp_path / "custom_agent" / "skills" / "cits-expert"
    syncer = SkillSynchronizer(home_dir=tmp_path)

    syncer.sync_to_directory(dest_dir, dry_run=False)

    assert (dest_dir / "SKILL.md").exists()
    assert (dest_dir / "references" / "packet-dissection.md").exists()
    assert (dest_dir / "references" / "standards-and-asn1.md").exists()
    assert (dest_dir / "references" / "topology-mapem-spatem.md").exists()
    assert (dest_dir / "references" / "priority-and-glosa.md").exists()
    assert (dest_dir / "references" / "hardware-and-capture.md").exists()
    assert (dest_dir / "references" / "anti-patterns-and-verification.md").exists()
    assert (dest_dir / "examples" / "python" / "dlt_unwrapper.py").exists()
