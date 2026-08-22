from .anomaly_rules import evaluate_anomaly_rules
from .anomaly_scoring import compute_anomaly_score


def run_anomaly(event: dict) -> dict:
    """
    Engine 1:
    - evaluates anomaly rules
    - computes anomaly score
    - writes into event['anomaly_detection']
    """
    rule_result = evaluate_anomaly_rules(event)
    score_result = compute_anomaly_score(rule_result, event)

    event["anomaly_detection"] = {
        "anomaly_score": score_result.get("anomaly_score", 0.0),
        "anomaly_level": score_result.get("anomaly_level", "none"),
        "anomaly_flags": score_result.get("anomaly_flags", []),
        "reasoning": score_result.get("reasoning", [])
    }

    return event
