import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import policy_analyzer as pa  # noqa: E402


@pytest.fixture(scope="session")
def all_results():
    return pa.analyze_all()


@pytest.fixture(scope="session")
def models():
    return {d: pa.load_design(d) for d in pa.DESIGNS}


@pytest.fixture
def mutated(tmp_path):
    """mutated(design, {device: [(old, new), ...]}) -> analyze() result on an edited copy of the configs."""
    def _make(design, edits):
        src = pa.CONFIGS / pa.DESIGN_DIRS[design]
        dst = tmp_path / design
        shutil.copytree(src, dst)
        for dev, pairs in edits.items():
            f = dst / f"{dev}.txt"
            text = f.read_text(encoding="utf-8")
            for old, new in pairs:
                assert old in text, f"{old!r} not in {dev}"
                text = text.replace(old, new)
            f.write_text(text, encoding="utf-8")
        return pa.analyze(design, dst)
    return _make


def attack(res, test_id, location_prefix=""):
    rows = [a for a in res["attacks"] if a["test_id"] == test_id and a["location"].startswith(location_prefix)]
    assert rows, (test_id, location_prefix)
    return rows
