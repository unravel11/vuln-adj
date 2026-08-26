from pathlib import Path
import importlib.util
import json


SCRIPT = Path(__file__).resolve().parents[1] / "build_jss_deterministic_tables.py"
SPEC = importlib.util.spec_from_file_location("build_jss_deterministic_tables", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def _analysis():
    status = {
        "severity": {"equivalent": 3106, "representation_discrepancy": 3178, "incomplete": 33, "factual_conflict": 1749},
        "affected_versions": {"equivalent": 425, "representation_discrepancy": 3936, "incomplete": 3054, "factual_conflict": 651},
        "published": {"representation_discrepancy": 6169, "temporal_discrepancy": 1897},
        "references": {"representation_discrepancy": 300, "incomplete": 7763, "factual_conflict": 3},
    }
    action_counts = {
        "field_aware_simple_v1": {
            "severity": {"no_action": 6279, "enrich_record": 33, "conflict_escalation": 1749, "abstain": 5},
            "affected_versions": {"no_action": 2734, "enrich_record": 3910, "conflict_escalation": 31, "abstain": 1391},
            "published": {"no_action": 6169, "wait_for_sync": 1897},
            "references": {"enrich_record": 8066},
        },
        "type_first_current_v1": {
            "severity": {"no_action": 6284, "enrich_record": 33, "conflict_escalation": 1749},
            "affected_versions": {"no_action": 4361, "enrich_record": 3054, "conflict_escalation": 651},
            "published": {"no_action": 6169, "wait_for_sync": 1897},
            "references": {"no_action": 300, "enrich_record": 7763, "conflict_escalation": 3},
        },
        "type_first_abstention_v1": {
            "severity": {"no_action": 6284, "enrich_record": 33, "conflict_escalation": 1491, "abstain": 258},
            "affected_versions": {"no_action": 2712, "enrich_record": 2980, "conflict_escalation": 215, "abstain": 2159},
            "published": {"no_action": 6169, "wait_for_sync": 1897},
            "references": {"no_action": 300, "enrich_record": 7763, "abstain": 3},
        },
    }
    return {
        "rows": 8066,
        "field_instances": 32264,
        "uses_any_labels": False,
        "label_is_human": False,
        "label_source": "none_label_free_policy_census",
        "eligible_for_accuracy_claim": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_policy_superiority_claim": False,
        "eligible_for_submission_readiness_claim": False,
        "eligible_for_workload_reduction_claim": False,
        "deterministic_status_counts": status,
        "policy_action_counts": action_counts,
        "pairwise_action_disagreement_counts": {
            "field_aware_simple_v1__vs__type_first_current_v1": {"severity": 5, "affected_versions": 2247, "references": 303},
            "field_aware_simple_v1__vs__type_first_abstention_v1": {"severity": 263, "affected_versions": 1766, "references": 303},
            "type_first_current_v1__vs__type_first_abstention_v1": {"severity": 258, "affected_versions": 2159, "references": 3},
        },
    }


def test_exact_rows_and_zero_fill(tmp_path):
    analysis_path = tmp_path / "analysis.json"
    analysis_path.write_text(json.dumps(_analysis()), encoding="utf-8")
    out = tmp_path / "out"
    MODULE.build(analysis_path, out)
    assert "Publication date,0,6169,0,1897,0,8066" in (out / "rq1_status_counts.csv").read_text()
    assert "Type-first current,17114,10850,1897,2403,0,2403,32264" in (out / "rq2_strategy_actions.csv").read_text()
    assert "Simple vs abstention-aware,263,1766,0,303,2332" in (out / "rq2_pairwise_disagreements.csv").read_text()


def test_rejects_human_or_accuracy_input():
    analysis = _analysis()
    analysis["uses_any_labels"] = True
    try:
        MODULE.build_rows(analysis)
    except ValueError as exc:
        assert "unsafe analysis flag" in str(exc)
    else:
        raise AssertionError("label-bearing input was accepted")
