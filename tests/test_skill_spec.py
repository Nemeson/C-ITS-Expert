import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = REPO_ROOT / "skill" / "cits-expert"
SKILL_MD = SKILL_DIR / "SKILL.md"


def parse_frontmatter(content: str) -> tuple[dict, str]:
    pattern = r"^---\s*\n(.*?)\n---\s*\n(.*)$"
    match = re.match(pattern, content, re.DOTALL)
    if not match:
        raise ValueError("Missing or invalid YAML frontmatter in SKILL.md")
    frontmatter_raw = match.group(1)
    body = match.group(2)
    data = yaml.safe_load(frontmatter_raw)
    return data, body


def test_skill_file_exists():
    assert SKILL_MD.exists(), f"SKILL.md not found at {SKILL_MD}"


def test_frontmatter_specification():
    content = SKILL_MD.read_text(encoding="utf-8")
    metadata, body = parse_frontmatter(content)

    assert metadata.get("name") == "cits-expert", "Skill name must be 'cits-expert'"
    description = metadata.get("description", "")
    assert description, "Skill description is required"
    assert description.startswith("Use when"), "Description must start with 'Use when...'"
    assert len(description) <= 1024, "Description exceeds 1024 characters"


def test_word_count_token_efficiency():
    content = SKILL_MD.read_text(encoding="utf-8")
    _, body = parse_frontmatter(content)
    words = body.split()
    word_count = len(words)
    assert word_count < 450, f"SKILL.md body word count ({word_count}) exceeds target limit of 450 words"


def test_routing_matrix_links_resolve():
    content = SKILL_MD.read_text(encoding="utf-8")
    # Find all markdown links like [Text](references/foo.md)
    links = re.findall(r"\[.*?\]\((references/[a-zA-Z0-9_-]+\.md)\)", content)
    assert len(links) >= 6, f"Expected at least 6 reference links in routing matrix, found {len(links)}"
    for link in links:
        target_path = SKILL_DIR / link
        assert target_path.exists(), f"Referenced file does not exist: {target_path}"


def test_polyglot_examples_exist():
    examples_dir = SKILL_DIR / "examples"
    expected_files = [
        examples_dir / "python" / "dlt_unwrapper.py",
        examples_dir / "rust" / "dissector.rs",
        examples_dir / "typescript" / "dlt_reader.ts",
        examples_dir / "javascript" / "dlt_reader.js",
        examples_dir / "cpp" / "dlt_dissector.hpp",
        examples_dir / "java" / "DltReader.java",
    ]
    for expected in expected_files:
        assert expected.exists(), f"Missing example file: {expected}"
        assert expected.stat().st_size > 0, f"Example file is empty: {expected}"


def test_changelog_exists_and_tracks_releases():
    changelog = REPO_ROOT / "CHANGELOG.md"
    assert changelog.exists(), "CHANGELOG.md must exist at repository root"
    content = changelog.read_text(encoding="utf-8")
    assert "## [Unreleased]" in content
    assert "## [1.2.0]" in content
    assert "## [1.1.0]" in content
    assert "## [1.0.0]" in content

