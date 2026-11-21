"""
NetSentry AI - Explainable Risk Scoring Engine
Calculates transparent risk scores (0-100) and severity classifications with itemized justification.
"""

from typing import Dict, Any


def calculate_risk_score(base_severity: str, factors: Dict[str, Any], anomaly_score: float = 0.0) -> Dict[str, Any]:
    """
    Computes an explainable, auditable risk score.
    
    Formula:
    - Base Severity Weights:
        Low: 25 points
        Medium: 50 points
        High: 75 points
        Critical: 90 points
    - Contextual Modifiers:
        + Sensitive/Critical port targeted: +15 points
        + Repeated recon/burst frequency: +10 to +15 points
        + Machine Learning anomaly concurrence: +10 to +20 points
        + External Non-RFC1918 traffic: +5 points
    
    Returns:
        {
            "score": int (0 - 100),
            "severity": str ("Low" | "Medium" | "High" | "Critical"),
            "explanation": str (Human-readable markdown breakdown)
        }
    """
    sev_map = {
        "LOW": 25,
        "MEDIUM": 50,
        "HIGH": 75,
        "CRITICAL": 90,
    }

    base = sev_map.get(base_severity.upper(), 30)
    current_score = base
    reasons = [f"Base score for {base_severity.upper()} severity: {base} pts"]

    # 1. Port scan or burst factor
    if "ports_scanned_count" in factors:
        p_count = factors["ports_scanned_count"]
        bonus = min(20, p_count * 2)
        current_score += bonus
        reasons.append(f"Port scan breadth ({p_count} distinct ports targeted): +{bonus} pts")

    if "syn_packet_count" in factors:
        s_count = factors["syn_packet_count"]
        bonus = min(20, int(s_count * 0.8))
        current_score += bonus
        reasons.append(f"SYN flood volume ({s_count} unacknowledged packets): +{bonus} pts")

    # 2. Sensitive port factor
    if "service_name" in factors:
        bonus = 15
        current_score += bonus
        reasons.append(f"Target is administrative or critical protocol ({factors['service_name']}): +{bonus} pts")

    # 3. Oversized payload factor
    if "packet_length" in factors:
        p_len = factors["packet_length"]
        if p_len > 1200:
            current_score += 15
            reasons.append(f"Excessive payload size ({p_len} bytes): +15 pts")

    # 4. ML Anomaly concurrence
    if anomaly_score < -0.10:
        ml_bonus = 15
        current_score += ml_bonus
        reasons.append(f"Isolation Forest identified statistical anomaly (Score: {anomaly_score:.3f}): +{ml_bonus} pts")

    # Cap score between 1 and 100
    final_score = max(5, min(100, current_score))

    # Map final score to standard SOC severity bands
    if final_score >= 85:
        severity = "Critical"
    elif final_score >= 65:
        severity = "High"
    elif final_score >= 40:
        severity = "Medium"
    else:
        severity = "Low"

    explanation = " | ".join(reasons)

    return {
        "score": final_score,
        "severity": severity,
        "explanation": explanation,
    }

