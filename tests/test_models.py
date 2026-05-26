from kisec.models import BenchmarkCase, EvidencePassage, Requirement, SystemPrediction


def test_dataclass_roundtrip():
    requirement = Requirement(
        requirement_id="IR-X",
        source="test",
        title="Test requirement",
        text="Incident response must be tested.",
        domain="Incident Management",
        expected_evidence_types=["testing"],
    )
    assert Requirement.from_dict(requirement.to_dict()) == requirement

    evidence = EvidencePassage(
        evidence_id="EV-1",
        document_id="DOC-1",
        section_title="Testing",
        text="A tabletop exercise tested incident response.",
        source_type="test_record",
        planted=True,
        metadata={"evidence_type": "testing"},
    )
    assert EvidencePassage.from_dict(evidence.to_dict()) == evidence

    case = BenchmarkCase(
        case_id="CASE-1",
        requirement_id="IR-X",
        company_document_ids=["DOC-1"],
        ground_truth_status="fulfilled",
        ground_truth_evidence_ids=["EV-1"],
        missing_evidence=[],
        rationale="All evidence exists.",
    )
    assert BenchmarkCase.from_dict(case.to_dict()) == case

    prediction = SystemPrediction(
        case_id="CASE-1",
        predicted_status="fulfilled",
        retrieved_evidence_ids=["EV-1"],
        explanation="Found testing.",
        confidence=0.9,
        unsupported_claims=[],
        model_or_method="test",
        config={"k": 1},
    )
    assert SystemPrediction.from_dict(prediction.to_dict()) == prediction
