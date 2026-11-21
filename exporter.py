"""
NetSentry AI - Security Incident and Traffic Report Exporter
Generates downloadable CSV reports and executive incident summary text for SOC analysts.
"""

import csv
import io
from typing import List, Dict, Any


def export_alerts_to_csv(alerts: List[Dict[str, Any]]) -> str:
    """Exports a list of alerts into a formatted CSV string."""
    output = io.StringIO()
    fieldnames = [
        "alert_id",
        "timestamp",
        "src_ip",
        "dst_ip",
        "detection_type",
        "rule_name",
        "severity",
        "risk_score",
        "description",
        "explanation",
        "status",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for alert in alerts:
        writer.writerow(alert)
    return output.getvalue()


def export_packets_to_csv(packets: List[Dict[str, Any]]) -> str:
    """Exports a list of packet records into a formatted CSV string."""
    output = io.StringIO()
    fieldnames = [
        "id",
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "length",
        "is_suspicious",
        "anomaly_score",
        "source_type",
        "info",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for packet in packets:
        writer.writerow(packet)
    return output.getvalue()


def generate_incident_summary_report(
    metrics: Dict[str, Any],
    recent_alerts: List[Dict[str, Any]],
    alert_counts: Dict[str, int]
) -> str:
    """Produces a clean executive markdown/text incident report."""
    total_packets = metrics.get("total_packets", 0)
    normal = metrics.get("normal_traffic", 0)
    suspicious = metrics.get("suspicious_traffic", 0)

    report_lines = [
        "=" * 70,
        "          NETSENTRY AI - SOC INCIDENT & THREAT REPORT",
        "=" * 70,
        "",
        "1. EXECUTIVE SUMMARY",
        f"   Total Network Packets Analysed : {total_packets:,}",
        f"   Normal Traffic Volume          : {normal:,}",
        f"   Suspicious / Anomalous Events  : {suspicious:,}",
        f"   Total Security Alerts Triggered: {alert_counts.get('Total', 0)}",
        "",
        "2. ALERT SEVERITY BREAKDOWN",
        f"   [!] Critical Severity          : {alert_counts.get('Critical', 0)}",
        f"   [-] High Severity              : {alert_counts.get('High', 0)}",
        f"   [-] Medium Severity            : {alert_counts.get('Medium', 0)}",
        f"   [o] Low Severity               : {alert_counts.get('Low', 0)}",
        "",
        "3. NOTABLE SECURITY INCIDENTS (LATEST ALERTS)",
    ]

    if not recent_alerts:
        report_lines.append("   No security alerts currently recorded.")
    else:
        for idx, alt in enumerate(recent_alerts[:10], start=1):
            report_lines.extend([
                f"   Incident #{idx}: [{alt.get('severity')}] {alt.get('rule_name')}",
                f"      Alert ID   : {alt.get('alert_id')}",
                f"      Timestamp  : {alt.get('timestamp')}",
                f"      Source IP  : {alt.get('src_ip')} -> Destination: {alt.get('dst_ip')}",
                f"      Risk Score : {alt.get('risk_score')}/100",
                f"      Details    : {alt.get('description')}",
                f"      Audit Trail: {alt.get('explanation')}",
                "",
            ])

    report_lines.extend([
        "=" * 70,
        "Report generated automatically by NetSentry AI Platform.",
        "Note: Passive monitoring and anomaly detections require human analyst verification.",
        "=" * 70,
    ])

    return "\n".join(report_lines)

