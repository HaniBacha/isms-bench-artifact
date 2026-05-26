#!/usr/bin/env python
from __future__ import annotations

import argparse
import base64
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.utils.io import read_json, write_json
from kisec.utils.tabular import read_csv

try:
    import matplotlib.pyplot as plt  # type: ignore
except Exception:
    plt = None


def _metric_table_tex(title: str, metrics: dict[str, float]) -> str:
    def tex_escape(value: str) -> str:
        return value.replace("_", "\\_")

    def format_value(key: str, value: float) -> str:
        if key.startswith("num_"):
            return str(int(value))
        return f"{value:.4f}"

    rows = "\n".join(
        f"{tex_escape(key)} & {format_value(key, value)} \\\\" for key, value in sorted(metrics.items())
    )
    return (
        "\\begin{table}[t]\n"
        "\\centering\n"
        f"\\caption{{{title}}}\n"
        "\\begin{tabular}{lr}\n"
        "\\toprule\n"
        "Metric & Value \\\\\n"
        "\\midrule\n"
        f"{rows}\n"
        "\\bottomrule\n"
        "\\end{tabular}\n"
        "\\end{table}\n"
    )


def _rows_to_latex_table(title: str, rows: list[dict[str, object]]) -> str:
    if not rows:
        return "% No rows available.\n"
    columns = list(rows[0].keys())
    def tex_escape(value: object) -> str:
        text = str(value)
        return (
            text.replace("\\", "\\textbackslash{}")
            .replace("_", "\\_")
            .replace("&", "\\&")
            .replace("%", "\\%")
            .replace("#", "\\#")
        )

    header = " & ".join(tex_escape(column) for column in columns) + " \\\\"
    body = "\n".join(
        " & ".join(tex_escape(row.get(column, "")) for column in columns) + " \\\\"
        for row in rows
    )
    return (
        "\\begin{table}[t]\n"
        "\\centering\n"
        f"\\caption{{{title}}}\n"
        "\\resizebox{\\linewidth}{!}{%\n"
        "\\begin{tabular}{" + "l" * len(columns) + "}\n"
        "\\toprule\n"
        f"{header}\n"
        "\\midrule\n"
        f"{body}\n"
        "\\bottomrule\n"
        "\\end{tabular}\n"
        "}\n"
        "\\end{table}\n"
    )


def _write_placeholder_png(path: Path) -> None:
    # 1x1 transparent PNG, used only when matplotlib is not installed.
    png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII="
    )
    path.write_bytes(png)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate artifact tables and figures from experiment outputs.")
    parser.add_argument("--method", default="bm25")
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--version", choices=["v01", "v02", "v03", "v04"], default="v01")
    args = parser.parse_args()

    tables_dir = ROOT / "artifact_outputs/tables"
    figures_dir = ROOT / "artifact_outputs/figures"
    tables_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    suffix = f"_{args.version}" if args.version in {"v02", "v03", "v04"} else ""
    retrieval_path = ROOT / f"experiments/results/retrieval_eval_{args.method}_k{args.k}{suffix}.json"
    compliance_path = ROOT / f"experiments/results/compliance_eval_{args.method}_k{args.k}{suffix}.json"
    attack_path = ROOT / f"experiments/results/attack_eval_{args.method}_k{args.k}{suffix}.json"

    generated = []
    if retrieval_path.exists():
        retrieval = read_json(retrieval_path)
        (tables_dir / "retrieval_metrics.tex").write_text(
            _metric_table_tex("Retrieval baseline results.", retrieval["metrics"]),
            encoding="utf-8",
        )
        generated.append("artifact_outputs/tables/retrieval_metrics.tex")
    if compliance_path.exists():
        compliance = read_json(compliance_path)
        (tables_dir / "compliance_metrics.tex").write_text(
            _metric_table_tex("Compliance classification baseline results.", compliance["metrics"]),
            encoding="utf-8",
        )
        generated.append("artifact_outputs/tables/compliance_metrics.tex")
    if attack_path.exists():
        attack = read_json(attack_path)
        (tables_dir / "attack_metrics.tex").write_text(
            _metric_table_tex("Attack robustness baseline results.", attack["metrics"]["overall"]),
            encoding="utf-8",
        )
        (tables_dir / "attack_metrics_by_type.tex").write_text(
            _rows_to_latex_table(
                "Attack metrics by type.",
                [
                    {
                        "attack_type": row["attack_type"],
                        "num_cases": row["num_cases"],
                        "attack_success_rate": row["attack_success_rate"],
                        "false_compliance_rate": row["false_compliance_rate"],
                        "status_flip_rate": row["status_flip_rate"],
                        "source_attribution_error_rate": row["source_attribution_error_rate"],
                    }
                    for row in attack["metrics"]["by_attack_type"]
                ],
            ),
            encoding="utf-8",
        )
        generated.extend(["artifact_outputs/tables/attack_metrics.tex", "artifact_outputs/tables/attack_metrics_by_type.tex"])

    if args.version == "v02":
        summary_path = ROOT / "experiments/results/summary_v02.csv"
        difficulty_path = ROOT / "experiments/results/by_difficulty_v02.csv"
        attack_type_path = ROOT / "experiments/results/by_attack_type_v02.csv"
        if summary_path.exists():
            rows = read_csv(summary_path)
            compact = [
                {
                    "baseline": row["baseline"],
                    "macro_f1": row["macro_f1"],
                    "evidence_f1": row["evidence_f1"],
                    "false_compliance_rate": row["false_compliance_rate"],
                    "performance_drop_under_mutation": row.get("performance_drop_under_mutation", ""),
                }
                for row in rows
            ]
            (tables_dir / "ablation_v02.tex").write_text(
                _rows_to_latex_table("ISMS-Bench v0.2 ablation results.", compact),
                encoding="utf-8",
            )
            generated.append("artifact_outputs/tables/ablation_v02.tex")
        if difficulty_path.exists():
            rows = read_csv(difficulty_path)
            sort_key = "macro_f1_present_labels" if rows and "macro_f1_present_labels" in rows[0] else "macro_f1"
            compact = sorted(rows, key=lambda row: float(row[sort_key]))[:10]
            (tables_dir / "hardest_difficulties_v02.tex").write_text(
                _rows_to_latex_table("Hardest v0.2 difficulty groups.", compact),
                encoding="utf-8",
            )
            generated.append("artifact_outputs/tables/hardest_difficulties_v02.tex")
        if attack_type_path.exists():
            rows = read_csv(attack_type_path)
            compact = sorted(rows, key=lambda row: float(row["attack_success_rate"]), reverse=True)[:12]
            (tables_dir / "attack_by_type_v02.tex").write_text(
                _rows_to_latex_table("Attack success by type in v0.2.", compact),
                encoding="utf-8",
            )
            generated.append("artifact_outputs/tables/attack_by_type_v02.tex")
    if args.version in {"v03", "v04"}:
        v = args.version
        summary_path = ROOT / f"experiments/results/summary_{v}.csv"
        by_split_path = ROOT / f"experiments/results/by_split_{v}.csv"
        ablation_path = ROOT / f"experiments/results/ablation_{v}.csv"
        attack_method_path = ROOT / ("experiments/results/attack_by_method_v03.csv" if v == "v03" else "experiments/results/attack_metrics_by_method_v04.csv")
        risk_path = ROOT / f"experiments/results/risk_weighted_errors_{v}.csv"
        attack_type_path = ROOT / ("experiments/results/by_attack_type_v03.csv" if v == "v03" else "experiments/results/attack_metrics_by_type_v04.csv")
        composition_rows = []
        for split in ["development_template", "heldout_template", "stress_test"]:
            path = ROOT / f"data/benchmark/summary_v03_{split}.json"
            if path.exists():
                summary = read_json(path)
                composition_rows.append(
                    {
                        "split": split,
                        "cases": summary["num_cases"],
                        "evidence": summary["num_evidence_passages"],
                        "fulfilled": summary["label_counts"]["fulfilled"],
                        "partial": summary["label_counts"]["partially_fulfilled"],
                        "not": summary["label_counts"]["not_fulfilled"],
                        "unclear": summary["label_counts"]["unclear"],
                    }
                )
        mutation_summary = ROOT / "data/benchmark/mutation_summary_v03.json"
        para_summary = ROOT / "data/benchmark/paraphrase_stress_summary_v04.json"
        attack_summary = ROOT / ("data/attacks/attack_summary_v03.json" if v == "v03" else "data/attacks/adaptive_attack_summary_v04.json")
        if mutation_summary.exists():
            summary = read_json(mutation_summary)
            composition_rows.append(
                {
                    "split": "mutation_cases",
                    "cases": summary["num_mutation_cases"],
                    "evidence": summary["num_mutation_evidence_passages"],
                    "fulfilled": "",
                    "partial": "",
                    "not": "",
                    "unclear": "",
                }
            )
        if v == "v04" and para_summary.exists():
            summary = read_json(para_summary)
            composition_rows.append(
                {
                    "split": "paraphrase_stress",
                    "cases": summary["num_cases"],
                    "evidence": summary["num_evidence_passages"],
                    "fulfilled": summary["label_counts"]["fulfilled"],
                    "partial": summary["label_counts"]["partially_fulfilled"],
                    "not": summary["label_counts"]["not_fulfilled"],
                    "unclear": summary["label_counts"]["unclear"],
                }
            )
        if attack_summary.exists():
            summary = read_json(attack_summary)
            composition_rows.append(
                {
                    "split": "attack_cases",
                    "cases": summary["num_attack_cases"],
                    "evidence": summary["num_attack_evidence_passages"],
                    "fulfilled": "",
                    "partial": "",
                    "not": "",
                    "unclear": "",
                }
            )
        (tables_dir / f"benchmark_composition_{v}.tex").write_text(
            _rows_to_latex_table(f"ISMS-Bench {v} benchmark composition.", composition_rows),
            encoding="utf-8",
        )
        generated.append(f"artifact_outputs/tables/benchmark_composition_{v}.tex")
        methods = [
            {"method": "random", "retrieval": "none", "metadata": "no", "provenance": "no", "policy": "random"},
            {"method": "majority", "retrieval": "none", "metadata": "no", "provenance": "no", "policy": "majority"},
            {"method": "bm25_metadata_blind_rules", "retrieval": "BM25", "metadata": "no", "provenance": "no", "policy": "rules"},
            {"method": "bm25_metadata_aware_rules", "retrieval": "BM25", "metadata": "yes", "provenance": "limited", "policy": "rules"},
            {"method": "tfidf_metadata_aware_rules", "retrieval": "TF-IDF", "metadata": "yes", "provenance": "limited", "policy": "rules"},
            {"method": "oracle_retrieval_metadata_aware_rules", "retrieval": "oracle", "metadata": "yes", "provenance": "limited", "policy": "rules"},
            {"method": "bm25_provenance_balanced", "retrieval": "BM25", "metadata": "yes", "provenance": "yes", "policy": "balanced"},
            {"method": "bm25_provenance_conservative", "retrieval": "BM25", "metadata": "yes", "provenance": "yes", "policy": "conservative"},
            {"method": "bm25_provenance_conservative_source_guard", "retrieval": "BM25", "metadata": "yes", "provenance": "yes", "policy": "guarded"},
        ]
        (tables_dir / f"methods_compared_{v}.tex").write_text(
            _rows_to_latex_table(f"Methods compared in {v}.", methods),
            encoding="utf-8",
        )
        generated.append(f"artifact_outputs/tables/methods_compared_{v}.tex")
        if summary_path.exists():
            rows = read_csv(summary_path)
            compact = [
                {
                    "method": row["baseline"],
                    "macro_f1": row["macro_f1"],
                    "false_compliance": row["false_compliance_rate"],
                    "abstention": row["abstention_rate"],
                    "risk_error": row["risk_weighted_error"],
                }
                for row in rows
            ]
            (tables_dir / f"overall_results_{v}.tex").write_text(
                _rows_to_latex_table(f"Overall {v} compliance results.", compact),
                encoding="utf-8",
            )
            generated.append(f"artifact_outputs/tables/overall_results_{v}.tex")
        if by_split_path.exists():
            rows = read_csv(by_split_path)
            compact = [
                {
                    "split": row["split"],
                    "macro_f1": row["macro_f1"],
                    "false_compliance": row["false_compliance_rate"],
                    "abstention": row["abstention_rate"],
                    "evidence_f1": row["evidence_f1"],
                }
                for row in rows
            ]
            (tables_dir / f"by_split_{v}.tex").write_text(
                _rows_to_latex_table(f"{v} performance by split for BM25 provenance-balanced.", compact),
                encoding="utf-8",
            )
            generated.append(f"artifact_outputs/tables/by_split_{v}.tex")
        if ablation_path.exists():
            rows = read_csv(ablation_path)
            compact = [
                {
                    "method": row["baseline"],
                    "macro_f1": row["macro_f1"],
                    "false_compliance": row["false_compliance_rate"],
                    "abstention": row["abstention_rate"],
                }
                for row in rows
            ]
            (tables_dir / f"ablation_{v}.tex").write_text(
                _rows_to_latex_table(f"{v} ablation study.", compact),
                encoding="utf-8",
            )
            generated.append(f"artifact_outputs/tables/ablation_{v}.tex")
        if attack_method_path.exists():
            rows = read_csv(attack_method_path)
            if v == "v04":
                rows = [row for row in rows if row.get("attack_suite") == "combined_attack_suite"]
            compact = [
                {
                    "method": row["method"],
                    "attack_success": row.get("attack_success_rate", ""),
                    "full_success": row.get("full_attack_success_rate", row.get("false_compliance_rate", "")),
                    "partial_success": row.get("partial_attack_success_rate", ""),
                    "residual_risk": row.get("residual_attack_risk_score", ""),
                    "abstention": row.get("classification_abstention_rate", row.get("abstention_rate", "")),
                }
                for row in rows
            ]
            (tables_dir / f"attack_results_{v}.tex").write_text(
                _rows_to_latex_table(f"{v} attack results by method.", compact),
                encoding="utf-8",
            )
            generated.append(f"artifact_outputs/tables/attack_results_{v}.tex")
        if risk_path.exists():
            rows = read_csv(risk_path)
            (tables_dir / f"risk_weighted_errors_{v}.tex").write_text(
                _rows_to_latex_table("Risk-weighted error and conservatism metrics.", rows),
                encoding="utf-8",
            )
            generated.append(f"artifact_outputs/tables/risk_weighted_errors_{v}.tex")
        if attack_type_path.exists():
            rows = read_csv(attack_type_path)
            if v == "v04":
                rows = [row for row in rows if row.get("attack_suite") in {"adaptive_attacks_v04", "combined_attack_suite"}]
            compact = sorted(rows, key=lambda row: float(row["attack_success_rate"]), reverse=True)[:15]
            (tables_dir / f"attack_by_type_{v}.tex").write_text(
                _rows_to_latex_table(f"Highest {v} attack success groups.", compact),
                encoding="utf-8",
            )
            generated.append(f"artifact_outputs/tables/attack_by_type_{v}.tex")
        if v == "v04":
            for path, out_name, title in [
                (ROOT / "experiments/results/adaptive_attack_v04.csv", "adaptive_attack_v04.tex", "Adaptive attack results."),
                (ROOT / "experiments/results/bootstrap_ci_v04.csv", "bootstrap_ci_v04.tex", "Bootstrap confidence intervals."),
                (ROOT / "experiments/results/method_comparison_tests_v04.csv", "method_comparison_tests_v04.tex", "Method comparison tests."),
            ]:
                if path.exists():
                    rows = read_csv(path)
                    if out_name == "bootstrap_ci_v04.tex":
                        rows = [
                            {
                                "surface": row["surface"],
                                "method": row["method"],
                                "metric": row["metric"],
                                "estimate": row["estimate"],
                                "ci_low": row["ci_low"],
                                "ci_high": row["ci_high"],
                            }
                            for row in rows[:18]
                        ]
                    if out_name == "adaptive_attack_v04.tex":
                        rows = [
                            {
                                "method": row["method"],
                                "attack_success": row["attack_success_rate"],
                                "full_success": row["full_attack_success_rate"],
                                "partial_success": row["partial_attack_success_rate"],
                                "residual_risk": row["residual_attack_risk_score"],
                            }
                            for row in rows
                        ]
                    (tables_dir / out_name).write_text(_rows_to_latex_table(title, rows), encoding="utf-8")
                    generated.append(f"artifact_outputs/tables/{out_name}")

        def save_or_placeholder(name: str, draw) -> None:
            figure_path = figures_dir / name
            if plt is None:
                _write_placeholder_png(figure_path)
            else:
                draw(figure_path)
            generated.append(str(figure_path.relative_to(ROOT)))

        def draw_attack(figure_path: Path) -> None:
            rows = read_csv(attack_method_path)
            if v == "v04":
                rows = [row for row in rows if row.get("attack_suite") == "combined_attack_suite"]
            labels = [row["method"].replace("_", "\n") for row in rows]
            values = [float(row.get("residual_attack_risk_score", row["attack_success_rate"])) for row in rows]
            fig, ax = plt.subplots(figsize=(8, 4))
            ax.bar(labels, values, color="#4c78a8")
            ax.set_ylabel("Residual attack risk" if v == "v04" else "Attack success rate")
            ax.set_ylim(0, max(1, max(values) * 1.15 if values else 1))
            ax.tick_params(axis="x", labelsize=7)
            fig.tight_layout()
            fig.savefig(figure_path, dpi=200)
            plt.close(fig)

        def draw_tradeoff(figure_path: Path) -> None:
            rows = read_csv(summary_path)
            label_map = {
                "random": "Random",
                "majority": "Majority",
                "bm25_metadata_blind_rules": "Metadata-blind",
                "bm25_metadata_aware_rules": "Metadata-aware",
                "tfidf_metadata_aware_rules": "TF-IDF meta.",
                "oracle_retrieval_metadata_aware_rules": "Oracle meta.",
                "bm25_provenance_balanced": "Prov.-balanced",
                "bm25_provenance_conservative": "Prov.-conservative",
                "bm25_provenance_conservative_source_guard": "Prov.-cons.+guard",
                "oracle_retrieval_provenance_balanced": "Oracle prov.-bal.",
            }
            markers = ["o", "s", "^", "D", "P", "X", "v", "<", ">", "*"]
            fig, ax = plt.subplots(figsize=(6.8, 4.5))
            for row in rows:
                idx = rows.index(row)
                label = label_map.get(row["baseline"], row["baseline"].replace("bm25_", "").replace("_", " "))
                ax.scatter(
                    float(row["abstention_rate"]),
                    float(row["false_compliance_rate"]),
                    s=78,
                    marker=markers[idx % len(markers)],
                    label=label,
                    edgecolor="black",
                    linewidth=0.4,
                    alpha=0.9,
                )
            ax.set_xlabel("Abstention rate")
            ax.set_ylabel("False compliance rate")
            ax.grid(True, linestyle=":", linewidth=0.6, alpha=0.7)
            ax.set_xlim(left=0)
            ax.set_ylim(bottom=0)
            ax.legend(
                loc="upper center",
                bbox_to_anchor=(0.5, -0.19),
                ncol=3,
                fontsize=7.2,
                frameon=False,
                handletextpad=0.4,
                columnspacing=0.8,
            )
            fig.tight_layout(rect=(0, 0.18, 1, 1))
            fig.savefig(figure_path, dpi=200)
            plt.close(fig)

        def draw_architecture(figure_path: Path) -> None:
            fig, ax = plt.subplots(figsize=(8, 2.8))
            ax.axis("off")
            boxes = ["Requirements", "Company evidence", "Retrieval", "Provenance assessor", "Metrics"]
            for idx, label in enumerate(boxes):
                ax.add_patch(plt.Rectangle((idx * 1.8, 0.8), 1.35, 0.75, fill=False, linewidth=1.5))
                ax.text(idx * 1.8 + 0.675, 1.175, label, ha="center", va="center", fontsize=9)
                if idx < len(boxes) - 1:
                    ax.arrow(idx * 1.8 + 1.38, 1.17, 0.35, 0, head_width=0.08, head_length=0.08, length_includes_head=True)
            ax.set_xlim(-0.1, 8.8)
            ax.set_ylim(0.4, 1.9)
            fig.tight_layout()
            fig.savefig(figure_path, dpi=200)
            plt.close(fig)

        def draw_pipeline(figure_path: Path) -> None:
            fig, ax = plt.subplots(figsize=(8, 3))
            ax.axis("off")
            boxes = ["Template families", "Atomic criteria", "Metadata variants", "Mutations", "Attacks", "Splits"]
            for idx, label in enumerate(boxes):
                ax.add_patch(plt.Rectangle((idx * 1.35, 0.8), 1.05, 0.75, fill=False, linewidth=1.5))
                ax.text(idx * 1.35 + 0.525, 1.175, label, ha="center", va="center", fontsize=8)
                if idx < len(boxes) - 1:
                    ax.arrow(idx * 1.35 + 1.08, 1.17, 0.22, 0, head_width=0.08, head_length=0.08, length_includes_head=True)
            ax.set_xlim(-0.1, 8.0)
            ax.set_ylim(0.4, 1.9)
            fig.tight_layout()
            fig.savefig(figure_path, dpi=200)
            plt.close(fig)

        def draw_split(figure_path: Path) -> None:
            rows = read_csv(by_split_path)
            labels = [row["split"].replace("_", "\n") for row in rows]
            values = [float(row["macro_f1"]) for row in rows]
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.bar(labels, values, color="#59a14f")
            ax.set_ylabel("Macro-F1")
            ax.set_ylim(0, 1)
            ax.tick_params(axis="x", labelsize=8)
            fig.tight_layout()
            fig.savefig(figure_path, dpi=200)
            plt.close(fig)

        if attack_method_path.exists():
            save_or_placeholder(f"attack_success_by_method_{v}.png", draw_attack)
        if summary_path.exists():
            save_or_placeholder(f"false_compliance_vs_abstention_{v}.png", draw_tradeoff)
        if by_split_path.exists():
            save_or_placeholder(f"split_performance_{v}.png", draw_split)
        save_or_placeholder(f"prototype_architecture_{v}.png", draw_architecture)
        save_or_placeholder(f"benchmark_generation_pipeline_{v}.png", draw_pipeline)

    confusion_path = ROOT / f"experiments/results/compliance_eval_{args.method}_k{args.k}{suffix}_confusion.csv"
    if args.version == "v02":
        confusion_path = ROOT / "experiments/results/confusion_matrix_v02.csv"
    if args.version in {"v03", "v04"}:
        confusion_path = ROOT / f"experiments/results/confusion_matrix_{args.version}.csv"
    if confusion_path.exists():
        rows = read_csv(confusion_path)
        labels = sorted({row["true_label"] for row in rows})
        pred_labels = sorted({row["predicted_label"] for row in rows})
        figure_path = figures_dir / (
            "compliance_confusion_matrix_v02.png"
            if args.version == "v02"
            else "compliance_confusion_matrix_v03.png"
            if args.version == "v03"
            else "compliance_confusion_matrix_v04.png"
            if args.version == "v04"
            else "compliance_confusion_matrix.png"
        )
        if plt is not None:
            grid = []
            for true in labels:
                grid.append(
                    [
                        int(
                            next(
                                row["count"]
                                for row in rows
                                if row["true_label"] == true and row["predicted_label"] == pred
                            )
                        )
                        for pred in pred_labels
                    ]
                )
            fig, ax = plt.subplots(figsize=(6, 4))
            image = ax.imshow(grid, cmap="Blues")
            ax.set_xticks(range(len(pred_labels)), pred_labels, rotation=30, ha="right")
            ax.set_yticks(range(len(labels)), labels)
            ax.set_xlabel("Predicted")
            ax.set_ylabel("Ground truth")
            for row_idx, row in enumerate(grid):
                for col_idx, value in enumerate(row):
                    ax.text(col_idx, row_idx, value, ha="center", va="center")
            fig.colorbar(image, ax=ax)
            fig.tight_layout()
            fig.savefig(figure_path, dpi=200)
            plt.close(fig)
        else:
            _write_placeholder_png(figure_path)
            (figures_dir / "compliance_confusion_matrix.txt").write_text(
                "matplotlib is not installed; install requirements.txt and rerun make_tables.py for the real figure.\n",
                encoding="utf-8",
            )
        generated.append(str(figure_path.relative_to(ROOT)))

    write_json(ROOT / "experiments/results/generated_artifact_outputs.json", {"generated": generated})
    print({"generated": generated})


if __name__ == "__main__":
    main()
