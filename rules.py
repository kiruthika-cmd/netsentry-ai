"""
NetSentry AI - Rule-Based Threat Detection Engine
Detects port scans, SYN floods, sensitive port intrusions, and abnormal traffic behavior.
Clearly distinguishes deterministic rule-based alerts from ML anomaly predictions.
"""

import time
from collections import defaultdict
from typing import Dict, Any, List, Optional
from src.detection.risk_scorer import calculate_risk_score

# High risk ports often probed by scanners or worms
CRITICAL_PORTS = {
    23: ("Telnet (Insecure Administrative Remote Access)", "High"),
    445: ("SMB (Server Message Block - Vulnerable to EternalBlue/WannaCry)", "Critical"),
    3389: ("RDP (Remote Desktop Protocol - Target for Brute Force)", "High"),
    1433: ("Microsoft SQL Server Direct Access", "High"),
    3306: ("MySQL Database Direct Internet Exposure", "Medium"),
    5900: ("VNC Remote Desktop Framebuffer", "Medium"),
    21: ("FTP (Cleartext File Transfer Protocol)", "Medium"),
}


class ThreatDetectionEngine:
    """
    Stateful rule-based engine tracking network connection metrics across time windows.
    """

    def __init__(self, port_scan_threshold: int = 8, window_seconds: float = 12.0):
        self.port_scan_threshold = port_scan_threshold
        self.window_seconds = window_seconds

        # Stateful memory: ip -> list of (timestamp, dst_port)
        self.port_access_history = defaultdict(list)
        # Stateful memory: ip -> list of timestamps for SYN packets
        self.syn_history = defaultdict(list)
        # Alert deduplication memory: (src_ip, rule_name) -> last_alert_time
        self.alert_suppression = {}

    def _clean_old_history(self, now: float):
        """Purges connection events older than the sliding window."""
        cutoff = now - self.window_seconds
        for ip in list(self.port_access_history.keys()):
            self.port_access_history[ip] = [
                (t, p) for (t, p) in self.port_access_history[ip] if t > cutoff
            ]
            if not self.port_access_history[ip]:
                del self.port_access_history[ip]

        for ip in list(self.syn_history.keys()):
            self.syn_history[ip] = [t for t in self.syn_history[ip] if t > cutoff]
            if not self.syn_history[ip]:
                del self.syn_history[ip]

    def _should_suppress(self, key: tuple, now: float, cooldown: float = 20.0) -> bool:
        """Suppresses duplicate alert spam from the same IP and rule within cooldown."""
        last_time = self.alert_suppression.get(key, 0)
        if now - last_time < cooldown:
            return True
        self.alert_suppression[key] = now
        return False

    def inspect_packet(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluates a single parsed packet against rule-based detection signatures.
        Returns a list of generated alert dictionaries (if any).
        """
        alerts = []
        now = time.time()
        self._clean_old_history(now)

        src_ip = packet.get("src_ip", "0.0.0.0")
        dst_ip = packet.get("dst_ip", "0.0.0.0")
        dst_port = int(packet.get("dst_port") or 0)
        protocol = packet.get("protocol", "").upper()
        flags = str(packet.get("tcp_flags") or "").upper()
        length = int(packet.get("length") or 0)

        # -------------------------------------------------------------
        # Rule 1: Port Scan Detection (Horizontal or Vertical Recon)
        # -------------------------------------------------------------
        if dst_port > 0:
            self.port_access_history[src_ip].append((now, dst_port))
            distinct_ports = {p for (_, p) in self.port_access_history[src_ip]}

            if len(distinct_ports) >= self.port_scan_threshold:
                if not self._should_suppress((src_ip, "RULE_PORT_SCAN"), now):
                    risk_info = calculate_risk_score(
                        base_severity="High",
                        factors={
                            "rule_triggered": "Port Scan Reconnaissance",
                            "ports_scanned_count": len(distinct_ports),
                            "target_ip": dst_ip,
                        }
                    )
                    alerts.append({
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "detection_type": "rule",
                        "rule_name": "RULE_PORT_SCAN",
                        "description": f"Port Scanning activity detected: {len(distinct_ports)} distinct ports targeted within {self.window_seconds:.0f}s.",
                        "severity": risk_info["severity"],
                        "risk_score": risk_info["score"],
                        "explanation": risk_info["explanation"],
                    })

        # -------------------------------------------------------------
        # Rule 2: TCP SYN Flood / SYN Burst Attempt
        # -------------------------------------------------------------
        if "S" in flags and "A" not in flags:  # Raw SYN without ACK
            self.syn_history[src_ip].append(now)
            syn_count = len(self.syn_history[src_ip])

            if syn_count >= 15:
                if not self._should_suppress((src_ip, "RULE_SYN_BURST"), now):
                    risk_info = calculate_risk_score(
                        base_severity="High",
                        factors={
                            "rule_triggered": "TCP SYN Burst / Potential DoS",
                            "syn_packet_count": syn_count,
                            "target_ip": dst_ip,
                        }
                    )
                    alerts.append({
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "detection_type": "rule",
                        "rule_name": "RULE_SYN_BURST",
                        "description": f"Abnormal TCP SYN flood/burst detected: {syn_count} unacknowledged SYN packets within {self.window_seconds:.0f}s.",
                        "severity": risk_info["severity"],
                        "risk_score": risk_info["score"],
                        "explanation": risk_info["explanation"],
                    })

        # -------------------------------------------------------------
        # Rule 3: High-Risk / Vulnerable Port Connection Attempt
        # -------------------------------------------------------------
        if dst_port in CRITICAL_PORTS:
            service_desc, default_sev = CRITICAL_PORTS[dst_port]
            if not self._should_suppress((src_ip, f"RULE_SENSITIVE_PORT_{dst_port}"), now, cooldown=30.0):
                risk_info = calculate_risk_score(
                    base_severity=default_sev,
                    factors={
                        "rule_triggered": f"Sensitive Port Probe: {dst_port}",
                        "service_name": service_desc,
                        "target_ip": dst_ip,
                    }
                )
                alerts.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "detection_type": "rule",
                    "rule_name": f"RULE_SENSITIVE_PORT_{dst_port}",
                    "description": f"Inbound connection targeted high-risk port {dst_port} ({service_desc}).",
                    "severity": risk_info["severity"],
                    "risk_score": risk_info["score"],
                    "explanation": risk_info["explanation"],
                })

        # -------------------------------------------------------------
        # Rule 4: Abnormal ICMP Packet Size (Oversized Ping)
        # -------------------------------------------------------------
        if protocol == "ICMP" and length > 1200:
            if not self._should_suppress((src_ip, "RULE_OVERSIZED_ICMP"), now, cooldown=20.0):
                risk_info = calculate_risk_score(
                    base_severity="Medium",
                    factors={
                        "rule_triggered": "Oversized ICMP Ping",
                        "packet_length": length,
                        "target_ip": dst_ip,
                    }
                )
                alerts.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "detection_type": "rule",
                    "rule_name": "RULE_OVERSIZED_ICMP",
                    "description": f"Abnormally large ICMP packet observed ({length} bytes). Typical pings are 32-64 bytes.",
                    "severity": risk_info["severity"],
                    "risk_score": risk_info["score"],
                    "explanation": risk_info["explanation"],
                })

        return alerts

