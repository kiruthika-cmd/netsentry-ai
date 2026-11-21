"""
NetSentry AI - Network Traffic Feature Engineering
Transforms raw packet dictionaries into numerical feature vectors for ML models.
"""

from typing import Dict, Any, List
import pandas as pd
import numpy as np

# High-risk / sensitive ports frequently targeted in network intrusions
SENSITIVE_PORTS = {21, 22, 23, 25, 53, 110, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 8080}

FEATURE_COLUMNS = [
    "length",
    "protocol_code",
    "src_port",
    "dst_port",
    "is_well_known_dst",
    "is_sensitive_port",
    "is_ephemeral_src",
    "has_syn_flag",
    "has_fin_or_rst_flag",
]


def extract_packet_features(packet: Dict[str, Any]) -> Dict[str, float]:
    """Extracts a single row of numerical features from a parsed packet dict."""
    proto_str = packet.get("protocol", "OTHER").upper()
    if "TCP" in proto_str or proto_str in ("HTTP", "HTTPS", "SSH", "FTP", "TELNET", "RDP", "SMB"):
        proto_code = 6.0
    elif "UDP" in proto_str or proto_str in ("DNS", "DHCP", "NTP", "SNMP"):
        proto_code = 17.0
    elif "ICMP" in proto_str:
        proto_code = 1.0
    elif "ARP" in proto_str:
        proto_code = 2.0
    else:
        proto_code = 0.0

    dst_p = float(packet.get("dst_port") or 0)
    src_p = float(packet.get("src_port") or 0)
    flags = str(packet.get("tcp_flags") or "").upper()

    return {
        "length": float(packet.get("length") or 60),
        "protocol_code": proto_code,
        "src_port": src_p,
        "dst_port": dst_p,
        "is_well_known_dst": 1.0 if dst_p < 1024 else 0.0,
        "is_sensitive_port": 1.0 if int(dst_p) in SENSITIVE_PORTS else 0.0,
        "is_ephemeral_src": 1.0 if src_p >= 1024 else 0.0,
        "has_syn_flag": 1.0 if "S" in flags else 0.0,
        "has_fin_or_rst_flag": 1.0 if ("F" in flags or "R" in flags) else 0.0,
    }


def packets_to_dataframe(packets: List[Dict[str, Any]]) -> pd.DataFrame:
    """Converts a list of parsed packets into a standardized feature DataFrame."""
    rows = [extract_packet_features(p) for p in packets]
    if not rows:
        return pd.DataFrame(columns=FEATURE_COLUMNS)
    return pd.DataFrame(rows)[FEATURE_COLUMNS]

