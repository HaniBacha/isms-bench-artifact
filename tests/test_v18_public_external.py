from __future__ import annotations

import json
import re
import subprocess
import sys
import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALID_LABELS = {"fulfilled", "partially_fulfilled", "not_fulfilled", "unclear"}
NON_IMPLEMENTATION_TYPES = {
    "public_template",
    "public_guidance",
    "public_regulatory_guidance",
    "control_catalog",
    "oscal_control",
    "assessment_template",
    "vendor_marketing_or_blog",
    "unknown_public_source",
}


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_v18_public_external_builder_outputs_required_files() -> None:
    subprocess.run([sys.executable, "scripts/build_public_external_validation_v18.py"], cwd=ROOT, check=True)
    required = [
        ROOT / "data/external_public/source_inventory_v18.csv",
        ROOT / "data/external_public/public_ir_evidence_corpus_v18.csv",
        ROOT / "data/external_public/public_ir_evidence_corpus_v18.jsonl",
        ROOT / "data/benchmark/public_external_validation_cases_v18.csv",
        ROOT / "data/benchmark/public_external_validation_cases_v18.jsonl",
        ROOT / "data/benchmark/public_external_review_sheet_v18.csv",
    ]
    for path in required:
        assert path.exists(), path


def test_v18_public_external_cases_are_well_formed() -> None:
    cases = _jsonl(ROOT / "data/benchmark/public_external_validation_cases_v18.jsonl")
    evidence = _jsonl(ROOT / "data/external_public/public_ir_evidence_corpus_v18.jsonl")
    evidence_ids = {row["evidence_id"] for row in evidence}
    assert 40 <= len(cases) <= 60
    for case in cases:
        assert case["expected_status"] in VALID_LABELS
        assert case["ground_truth_status"] == case["expected_status"]
        assert case["label_author"] == "project_initial"
        assert case["external_review_status"] == "pending"
        assert case["source_ids"]
        assert case["source_urls"]
        assert all(str(url).startswith("https://") for url in case["source_urls"])
        assert set(case["accepted_evidence_ids"]).issubset(evidence_ids)
        assert set(case["rejected_evidence_ids"]).issubset(evidence_ids)
        assert "criteria_truth" in case
        assert case["criteria_truth"] == {}


def test_v18_public_external_evidence_has_redistribution_and_no_full_text() -> None:
    evidence = _jsonl(ROOT / "data/external_public/public_ir_evidence_corpus_v18.jsonl")
    assert len(evidence) >= 40
    for row in evidence:
        assert row["source_id"]
        assert row["source_url"].startswith("https://")
        assert row["redistribution_note"]
        text = row["short_excerpt_or_paraphrase"]
        assert text.startswith("Paraphrase:")
        assert len(text.split()) <= 45
        assert row["source_type"]
        assert row["criterion_tags"]


def test_v18_public_external_files_do_not_contain_local_paths_or_secrets() -> None:
    paths = [
        ROOT / "data/external_public/source_inventory_v18.csv",
        ROOT / "data/external_public/public_ir_evidence_corpus_v18.csv",
        ROOT / "data/external_public/public_ir_evidence_corpus_v18.jsonl",
        ROOT / "data/benchmark/public_external_validation_cases_v18.csv",
        ROOT / "data/benchmark/public_external_validation_cases_v18.jsonl",
        ROOT / "data/benchmark/public_external_review_sheet_v18.csv",
    ]
    forbidden = re.compile("(" + "/" + "home" + "/" + r"|\\\\Users\\\\|JGU_API_KEY|KI_CHAT_API_KEY|Bearer\\s+|sk-[A-Za-z0-9])")
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert not forbidden.search(text), path


def test_v18_public_external_evaluator_writes_outputs() -> None:
    subprocess.run([sys.executable, "scripts/run_public_external_validation_eval_v18.py"], cwd=ROOT, check=True)
    assert (ROOT / "experiments/results/public_external_validation_v18.csv").exists()
    assert (ROOT / "experiments/results/public_external_validation_analysis_v18.md").exists()


def test_v18b_public_external_builder_outputs_taxonomy_files() -> None:
    subprocess.run([sys.executable, "scripts/build_public_external_validation_v18b.py"], cwd=ROOT, check=True)
    required = [
        ROOT / "data/external_public/source_inventory_v18b.csv",
        ROOT / "data/external_public/public_ir_evidence_corpus_v18b.csv",
        ROOT / "data/external_public/public_ir_evidence_corpus_v18b.jsonl",
        ROOT / "data/benchmark/public_external_validation_cases_v18b.csv",
        ROOT / "data/benchmark/public_external_validation_cases_v18b.jsonl",
        ROOT / "data/benchmark/public_external_review_sheet_v18b.csv",
    ]
    for path in required:
        assert path.exists(), path


def test_v18b_sources_and_evidence_have_canonical_source_types() -> None:
    sources = _csv(ROOT / "data/external_public/source_inventory_v18b.csv")
    evidence = _jsonl(ROOT / "data/external_public/public_ir_evidence_corpus_v18b.jsonl")
    assert sources
    assert evidence
    for row in sources:
        assert row["canonical_source_type"]
        assert row["implementation_evidence_allowed"] in {"True", "False", "true", "false"}
        assert row["rationale_for_source_type"]
    for row in evidence:
        assert row["canonical_source_type"]
        assert isinstance(row["implementation_evidence_allowed"], bool)
        assert row["rationale_for_source_type"]
        assert row["metadata"]["canonical_source_type"] == row["canonical_source_type"]
        assert row["metadata"]["implementation_evidence_allowed"] == row["implementation_evidence_allowed"]


def test_v18b_cases_are_well_formed_and_review_marked() -> None:
    cases = _jsonl(ROOT / "data/benchmark/public_external_validation_cases_v18b.jsonl")
    evidence = _jsonl(ROOT / "data/external_public/public_ir_evidence_corpus_v18b.jsonl")
    evidence_ids = {row["evidence_id"] for row in evidence}
    assert 40 <= len(cases) <= 60
    for case in cases:
        assert case["expected_status"] in VALID_LABELS
        assert case["ground_truth_status"] == case["expected_status"]
        assert case["label_author"] == "project_initial"
        assert case["external_review_status"] == "pending"
        assert case["case_cleanup_status"] in {
            "retained_clean",
            "revised",
            "needs_human_review",
            "excluded_from_eval_pending_review",
        }
        assert case["original_case_id"].startswith("PUBEXT18-")
        assert case["source_ids"]
        assert case["source_urls"]
        assert all(str(url).startswith("https://") for url in case["source_urls"])
        assert set(case["accepted_evidence_ids"]).issubset(evidence_ids)
        assert set(case["rejected_evidence_ids"]).issubset(evidence_ids)
        assert case["source_type_taxonomy_version"] == "v18b"
        assert case["canonical_source_types"]


def test_v18b_does_not_accept_guidance_as_fulfilled_implementation_evidence() -> None:
    cases = _jsonl(ROOT / "data/benchmark/public_external_validation_cases_v18b.jsonl")
    evidence = _jsonl(ROOT / "data/external_public/public_ir_evidence_corpus_v18b.jsonl")
    evidence_by_id = {row["evidence_id"]: row for row in evidence}
    for case in cases:
        if case["expected_status"] != "fulfilled":
            continue
        for evidence_id in case["accepted_evidence_ids"]:
            canonical = evidence_by_id[evidence_id]["canonical_source_type"]
            assert canonical not in NON_IMPLEMENTATION_TYPES, (case["case_id"], evidence_id, canonical)
            assert evidence_by_id[evidence_id]["implementation_evidence_allowed"] is True


def test_v18b_files_do_not_contain_local_paths_or_secrets() -> None:
    paths = [
        ROOT / "data/external_public/source_inventory_v18b.csv",
        ROOT / "data/external_public/public_ir_evidence_corpus_v18b.csv",
        ROOT / "data/external_public/public_ir_evidence_corpus_v18b.jsonl",
        ROOT / "data/benchmark/public_external_validation_cases_v18b.csv",
        ROOT / "data/benchmark/public_external_validation_cases_v18b.jsonl",
        ROOT / "data/benchmark/public_external_review_sheet_v18b.csv",
    ]
    forbidden = re.compile("(" + "/" + "home" + "/" + r"|\\\\Users\\\\|JGU_API_KEY|KI_CHAT_API_KEY|Bearer\\s+|sk-[A-Za-z0-9])")
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert not forbidden.search(text), path


def test_v18b_evaluator_and_error_analysis_write_outputs() -> None:
    subprocess.run([sys.executable, "scripts/run_public_external_validation_eval_v18b.py"], cwd=ROOT, check=True)
    subprocess.run([sys.executable, "scripts/analyze_public_external_errors_v18b.py"], cwd=ROOT, check=True)
    required = [
        ROOT / "experiments/results/public_external_validation_v18b.csv",
        ROOT / "experiments/results/public_external_validation_analysis_v18b.md",
        ROOT / "experiments/results/public_external_error_analysis_v18b.csv",
        ROOT / "experiments/results/public_external_error_analysis_v18b.md",
        ROOT / "data/benchmark/public_external_human_review_priority_v18b.csv",
    ]
    for path in required:
        assert path.exists(), path


def test_v18c_builder_outputs_review_ready_files() -> None:
    subprocess.run([sys.executable, "scripts/build_public_external_validation_v18c.py"], cwd=ROOT, check=True)
    required = [
        ROOT / "data/benchmark/public_external_validation_cases_v18c.csv",
        ROOT / "data/benchmark/public_external_validation_cases_v18c.jsonl",
        ROOT / "data/benchmark/public_external_review_sheet_v18c.csv",
        ROOT / "data/benchmark/public_external_human_review_priority_v18c.csv",
    ]
    for path in required:
        assert path.exists(), path


def test_v18c_priority_sheet_covers_all_cases() -> None:
    cases = _jsonl(ROOT / "data/benchmark/public_external_validation_cases_v18c.jsonl")
    priority = _csv(ROOT / "data/benchmark/public_external_human_review_priority_v18c.csv")
    assert len(cases) == 46
    assert len(priority) == 46
    assert {row["case_id"] for row in priority} == {case["case_id"] for case in cases}
    assert "PUBEXT18B-039" in {row["case_id"] for row in priority}


def test_v18c_cases_have_evidence_semantics_and_case_type() -> None:
    cases = _jsonl(ROOT / "data/benchmark/public_external_validation_cases_v18c.jsonl")
    valid_case_types = {
        "public_org_evidence_validation",
        "public_source_confusion_stress",
        "public_template_guidance_stress",
        "public_unclear_evidence_stress",
    }
    for case in cases:
        assert "supporting_evidence_ids" in case
        assert "sufficient_evidence_ids" in case
        assert "insufficient_or_context_evidence_ids" in case
        assert case["criterion_operator"] == "all"
        assert case["case_type"] in valid_case_types
        assert isinstance(case["composite_requirement"], bool)
        assert isinstance(case["criteria_count"], int)
        assert case["criteria_count"] == len(case["expected_criteria"])
        assert case["composite_requirement"] == (case["criteria_count"] > 2)
        assert case["expected_status"] in VALID_LABELS
        assert case["label_author"] == "project_initial"
        assert case["external_review_status"] == "pending"


def test_v18c_evidence_semantic_ids_exist() -> None:
    cases = _jsonl(ROOT / "data/benchmark/public_external_validation_cases_v18c.jsonl")
    evidence = _jsonl(ROOT / "data/external_public/public_ir_evidence_corpus_v18b.jsonl")
    evidence_ids = {row["evidence_id"] for row in evidence}
    for case in cases:
        for field in [
            "accepted_evidence_ids",
            "supporting_evidence_ids",
            "sufficient_evidence_ids",
            "insufficient_or_context_evidence_ids",
            "rejected_evidence_ids",
        ]:
            assert set(case[field]).issubset(evidence_ids), (case["case_id"], field)


def test_v18c_non_implementation_sources_are_not_sufficient_for_fulfilled() -> None:
    cases = _jsonl(ROOT / "data/benchmark/public_external_validation_cases_v18c.jsonl")
    evidence = _jsonl(ROOT / "data/external_public/public_ir_evidence_corpus_v18b.jsonl")
    evidence_by_id = {row["evidence_id"]: row for row in evidence}
    for case in cases:
        if case["expected_status"] != "fulfilled":
            continue
        for evidence_id in case["sufficient_evidence_ids"]:
            evidence_row = evidence_by_id[evidence_id]
            assert evidence_row["canonical_source_type"] not in NON_IMPLEMENTATION_TYPES
            assert evidence_row["implementation_evidence_allowed"] is True


def test_v18c_files_do_not_contain_local_paths_or_secrets() -> None:
    paths = [
        ROOT / "data/benchmark/public_external_validation_cases_v18c.csv",
        ROOT / "data/benchmark/public_external_validation_cases_v18c.jsonl",
        ROOT / "data/benchmark/public_external_review_sheet_v18c.csv",
        ROOT / "data/benchmark/public_external_human_review_priority_v18c.csv",
    ]
    forbidden = re.compile("(" + "/" + "home" + "/" + r"|\\\\Users\\\\|JGU_API_KEY|KI_CHAT_API_KEY|Bearer\\s+|sk-[A-Za-z0-9])")
    for path in paths:
        assert not forbidden.search(path.read_text(encoding="utf-8")), path


def test_v18c_diagnostic_evaluator_writes_outputs() -> None:
    subprocess.run([sys.executable, "scripts/run_public_external_validation_eval_v18c.py", "--seed", "42"], cwd=ROOT, check=True)
    assert (ROOT / "experiments/results/public_external_validation_v18c.csv").exists()
    assert (ROOT / "experiments/results/public_external_validation_analysis_v18c.md").exists()
