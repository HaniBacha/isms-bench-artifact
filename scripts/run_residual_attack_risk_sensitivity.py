#!/usr/bin/env python
from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


WEIGHT_SETTINGS = {
    "primary": {
        "full_attack_success_rate": 1.0,
        "unsafe_evidence_acceptance_rate": 0.55,
        "source_attribution_failure_rate": 0.45,
        "partial_non_full_success": 0.25,
    },
    "full_success_heavy": {
        "full_attack_success_rate": 1.5,
        "unsafe_evidence_acceptance_rate": 0.50,
        "source_attribution_failure_rate": 0.40,
        "partial_non_full_success": 0.20,
    },
    "unsafe_evidence_heavy": {
        "full_attack_success_rate": 1.0,
        "unsafe_evidence_acceptance_rate": 1.20,
        "source_attribution_failure_rate": 0.45,
        "partial_non_full_success": 0.20,
    },
    "source_error_heavy": {
        "full_attack_success_rate": 1.0,
        "unsafe_evidence_acceptance_rate": 0.55,
        "source_attribution_failure_rate": 1.20,
        "partial_non_full_success": 0.20,
    },
    "equalized_components": {
        "full_attack_success_rate": 1.0,
        "unsafe_evidence_acceptance_rate": 1.0,
        "source_attribution_failure_rate": 1.0,
        "partial_non_full_success": 1.0,
    },
}


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    source_path = ROOT / "experiments/results/combined_attack_v04.csv"
    rows = _read_csv(source_path)
    if not rows:
        raise SystemExit(f"No rows found in {source_path}")

    output_rows: list[dict[str, object]] = []
    for setting, weights in WEIGHT_SETTINGS.items():
        for row in rows:
            full = float(row["full_attack_success_rate"])
            unsafe = float(row["unsafe_evidence_acceptance_rate"])
            source = float(row["source_attribution_failure_rate"])
            partial_non_full = max(float(row["partial_attack_success_rate"]), float(row["false_partial_or_fulfilled_rate"]))
            risk = (
                weights["full_attack_success_rate"] * full
                + weights["unsafe_evidence_acceptance_rate"] * unsafe
                + weights["source_attribution_failure_rate"] * source
                + weights["partial_non_full_success"] * partial_non_full
            )
            output_rows.append(
                {
                    "setting": setting,
                    "method": row["method"],
                    "full_attack_success_rate": f"{full:.3f}",
                    "unsafe_evidence_acceptance_rate": f"{unsafe:.3f}",
                    "source_attribution_failure_rate": f"{source:.3f}",
                    "partial_non_full_success": f"{partial_non_full:.3f}",
                    "residual_attack_risk": f"{risk:.3f}",
                }
            )

    out_csv = ROOT / "experiments/results/residual_attack_risk_sensitivity_v29.csv"
    _write_csv(out_csv, output_rows)

    lines = [
        "# Residual Attack Risk Sensitivity Check",
        "",
        "This script recomputes residual attack risk from existing combined attack-suite component metrics. It does not add new predictions or change the paper's main result tables.",
        "",
        "Weight settings:",
    ]
    for setting, weights in WEIGHT_SETTINGS.items():
        lines.append(
            f"- `{setting}`: full={weights['full_attack_success_rate']}, unsafe={weights['unsafe_evidence_acceptance_rate']}, source={weights['source_attribution_failure_rate']}, partial={weights['partial_non_full_success']}"
        )
    lines.extend(["", "Lowest-risk method by setting:"])
    for setting in WEIGHT_SETTINGS:
        setting_rows = [row for row in output_rows if row["setting"] == setting]
        best = min(setting_rows, key=lambda row: float(row["residual_attack_risk"]))
        lines.append(f"- `{setting}`: `{best['method']}` with residual attack risk {best['residual_attack_risk']}")
    lines.extend(
        [
            "",
            "Interpretation: this is a diagnostic robustness check for the aggregate metric, not a validated organizational loss function. Component metrics remain the primary evidence.",
        ]
    )
    out_md = ROOT / "experiments/results/residual_attack_risk_sensitivity_v29.md"
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print({"csv": str(out_csv.relative_to(ROOT)), "md": str(out_md.relative_to(ROOT)), "rows": len(output_rows)})


if __name__ == "__main__":
    main()
