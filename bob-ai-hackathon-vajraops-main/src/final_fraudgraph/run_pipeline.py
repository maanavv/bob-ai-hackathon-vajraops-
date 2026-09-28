#!/usr/bin/env python3
"""Run Phase 1 (normalization) and Phase 2 (analysis) on a raw evidence folder."""

import argparse
import json
from pathlib import Path

from normalizer.engine import NormalizationEngine
from analyzer.engine import AnalyzerEngine
from utils.ids import safe_case_id


SUPPORTED = {".csv", ".json", ".xlsx", ".xls", ".txt", ".pdf"}


def main() -> None:
    parser = argparse.ArgumentParser(description="FraudGraph: normalize raw evidence, then analyze it")
    parser.add_argument("input_dir", help="Folder containing raw evidence files")
    parser.add_argument("--case-id", default="CASE001")
    parser.add_argument("--title", default="Cyber Fraud Investigation")
    parser.add_argument("--output-dir", default=None)
    args = parser.parse_args()

    case_id = safe_case_id(args.case_id)
    input_dir = Path(args.input_dir).resolve()
    if not input_dir.is_dir():
        raise SystemExit(f"Input folder not found: {input_dir}")

    output_dir = Path(args.output_dir).resolve() if args.output_dir else input_dir.parent / case_id / "generated"
    output_dir.mkdir(parents=True, exist_ok=True)

    normalizer = NormalizationEngine(case_id=case_id, title=args.title)
    files = sorted(p for p in input_dir.iterdir() if p.is_file() and p.suffix.lower() in SUPPORTED and p.name.lower() != "graph.json")
    if not files:
        raise SystemExit(f"No supported evidence files found in {input_dir}")

    print("PHASE 1 — NORMALIZATION")
    for path in files:
        print(f"  processing: {path.name}")
        normalizer.process_file(path.name, path.read_bytes())

    normalized = normalizer.finalize()
    normalized_path = output_dir / "case.json"
    normalized_path.write_text(json.dumps(normalized, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"  normalized JSON: {normalized_path}")
    print(f"  persons: {len(normalized.get('persons', []))}")
    print(f"  devices: {len(normalized.get('devices', []))}")
    print(f"  transactions: {len(normalized.get('transactions', []))}")
    print(f"  calls: {len(normalized.get('calls', []))}")
    print(f"  sim events: {len(normalized.get('sim_events', []))}")
    print(f"  evidence: {len(normalized.get('evidence', []))}")

    print("\nPHASE 2 — ANALYSIS")
    analysis = AnalyzerEngine(normalized).analyze()
    analysis_path = output_dir / "case_analysis.json"
    analysis_path.write_text(json.dumps(analysis, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"  analysis JSON: {analysis_path}")
    print(f"  subjects: {len(analysis.get('subject_profiles', []))}")
    print(f"  findings: {len(analysis.get('findings', []))}")
    print(f"  person edges: {analysis['network']['edge_count']}")
    print(f"  entity edges: {analysis['network']['entity_network']['edge_count']}")
    print(f"  patterns: {sorted({f['pattern_type'] for f in analysis.get('findings', [])})}")
    print("\nPIPELINE COMPLETE")


if __name__ == "__main__":
    main()
