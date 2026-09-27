import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PY_EXAMPLES = REPO_ROOT / "skill" / "cits-expert" / "examples" / "python"

if str(PY_EXAMPLES) not in sys.path:
    sys.path.insert(0, str(PY_EXAMPLES))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
