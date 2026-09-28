#!/usr/bin/env python3
"""CLI wrapper for the second-stage investigation analyzer."""

import argparse
import json
from pathlib import Path

from analyzer.engine import load_and_analyze


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze a normalized FraudGraph case JSON")
    parser.add_argument("input", help="Path to normalized case.json")
    parser.add_argument("-o", "--output", help="Output path; defaults to <input>_analysis.json")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else input_path.with_name(input_path.stem + "_analysis.json")
    result = load_and_analyze(input_path)
    output_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Analysis written to: {output_path}")
    print(f"Subjects: {len(result['subject_profiles'])}")
    print(f"Findings: {len(result['findings'])}")
    print(f"Person-network edges: {result['network']['edge_count']}")
    print(f"Entity-network edges: {result['network']['entity_network']['edge_count']}")


if __name__ == "__main__":
    main()
