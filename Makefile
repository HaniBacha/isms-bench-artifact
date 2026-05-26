PYTHON ?= .venv/bin/python
PYTHON_BOOTSTRAP ?= python3
PIP ?= .venv/bin/pip

.PHONY: setup test data eval eval-small tables figures leakage-check label-audit sensitivity artifact-check llm-smoke public-diagnostic

setup:
	$(PYTHON_BOOTSTRAP) -m venv .venv
	$(PIP) install -r requirements.txt

test:
	$(PYTHON) -m pytest

data:
	$(PYTHON) scripts/build_corpus.py
	$(PYTHON) scripts/generate_synthetic_cases.py --version v03 --split development_template --seed 42
	$(PYTHON) scripts/generate_synthetic_cases.py --version v03 --split heldout_template --seed 42
	$(PYTHON) scripts/generate_synthetic_cases.py --version v03 --split stress_test --seed 42
	$(PYTHON) scripts/generate_mutation_cases.py --seed 42
	$(PYTHON) scripts/generate_paraphrase_stress_v04.py --seed 42

eval:
	$(PYTHON) scripts/run_retrieval_eval.py --method bm25 --k 5 --version v04
	$(PYTHON) scripts/run_compliance_eval.py --method bm25 --k 5 --version v04
	$(PYTHON) scripts/run_attack_eval.py --method bm25 --k 5 --version v04

eval-small:
	PYTHONPATH=src $(PYTHON) -c "from kisec.corpus.synthetic import generate_incident_response_dataset; from kisec.ingestion.requirements import DEFAULT_INCIDENT_REQUIREMENTS_V02 as R; d=generate_incident_response_dataset(R, num_cases=500, seed=42, version='v02'); print({'cases': len(d.benchmark_cases), 'evidence': len(d.evidence_passages)})"
	PYTHONPATH=src $(PYTHON) -c "from kisec.corpus.synthetic import generate_incident_response_dataset; from kisec.ingestion.requirements import DEFAULT_INCIDENT_REQUIREMENTS_V02 as R; from kisec.compliance.rule_based import ConstantStatusComplianceAssessor; from kisec.evaluation.metrics import compliance_metrics; d=generate_incident_response_dataset(R, num_cases=500, seed=42, version='v02'); cases=d.benchmark_cases[:20]; preds=[ConstantStatusComplianceAssessor('unclear').predict(c.to_prediction_input(), R[0], {}, []) for c in cases]; print(compliance_metrics(cases, preds))"

tables:
	$(PYTHON) scripts/make_tables.py --version v04

figures: tables

artifact-check:
	$(PYTHON) -m pytest
	$(PYTHON) scripts/check_label_leakage.py
	$(PYTHON) scripts/check_generator_coupling.py
	$(PYTHON) scripts/run_label_audit.py

leakage-check:
	$(PYTHON) scripts/check_label_leakage.py
	$(PYTHON) scripts/check_generator_coupling.py

label-audit:
	$(PYTHON) scripts/run_label_audit.py

sensitivity:
	$(PYTHON) scripts/run_residual_attack_risk_sensitivity.py

public-diagnostic:
	$(PYTHON) scripts/build_public_external_validation_v18c.py
	$(PYTHON) scripts/run_public_external_validation_eval_v18c.py

llm-smoke:
	$(PYTHON) scripts/check_llm_env_v14.py
	$(PYTHON) scripts/run_llm_baselines_v13.py --seed 42 --max-cases 5 --dry-run --output-stem llm_mock_smoke
