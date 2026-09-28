import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analyzer.engine import AnalyzerEngine


CASE_PATH = ROOT / "data" / "cases" / "001" / "normalized" / "case.json"


def test_analyzer_smoke():
    case = json.loads(CASE_PATH.read_text(encoding="utf-8"))
    result = AnalyzerEngine(case).analyze()

    assert len(result["subject_profiles"]) >= 1
    assert len(result["findings"]) >= 1
    assert result["network"]["edge_count"] >= 1

    pattern_types = {finding["pattern_type"] for finding in result["findings"]}
    assert "RAPID_FAN_OUT" in pattern_types
    assert "RAPID_FAN_IN" in pattern_types


if __name__ == "__main__":
    test_analyzer_smoke()
    print("Analyzer smoke test: PASS")
