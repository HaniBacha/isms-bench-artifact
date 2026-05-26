#!/usr/bin/env python
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.utils.io import write_json
from kisec.utils.tabular import write_csv


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> None:
    parser = argparse.ArgumentParser(description="Create ablation summary tables from compliance results.")
    parser.add_argument("--version", choices=["v02", "v03", "v04"], default="v03")
    args = parser.parse_args()

    summary_path = ROOT / f"experiments/results/summary_{args.version}.csv"
    if not summary_path.exists():
        raise SystemExit(f"Missing {summary_path}; run scripts/run_compliance_eval.py first.")
    rows = _read_csv(summary_path)
    out_path = ROOT / f"experiments/results/ablation_{args.version}.csv"
    write_csv(out_path, rows)
    write_json(
        ROOT / f"experiments/results/ablation_{args.version}.json",
        {
            "version": args.version,
            "num_methods": len(rows),
            "methods": [row.get("baseline", row.get("method", "")) for row in rows],
        },
    )
    print(f"Wrote {out_path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
