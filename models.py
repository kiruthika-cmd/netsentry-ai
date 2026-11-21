"""
NetSentry AI - Database Models and Data Access Layer
Provides parameterized queries for packets, alerts, metrics, and incident reporting.
"""

import json
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from src.database.db import get_db


class PacketRepository:
    """Handles all database operations related to network packets."""

    @staticmethod
    def insert_packet(packet_data: Dict[str, Any]) -> int:
        """Inserts a single analyzed packet into the database."""
        sql = """
        INSERT INTO packets (
            timestamp, src_ip, dst_ip, src_port, dst_port,
            protocol, length, info, is_suspicious, anomaly_score, source_type
        ) VALUES (
            :timestamp, :src_ip, :dst_ip, :src_port, :dst_port,
            :protocol, :length, :info, :is_suspicious, :anomaly_score, :source_type
        )
        """
        # Ensure default timestamp if not present
        if "timestamp" not in packet_data or not packet_data["timestamp"]:
            packet_data["timestamp"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        with get_db().get_cursor() as cursor:
            cursor.execute(sql, packet_data)
            return cursor.lastrowid

    @staticmethod
    def insert_packets_bulk(packets_list: List[Dict[str, Any]]):
        """Inserts a list of packets in a single bulk transaction for optimal performance."""
        if not packets_list:
            return
        sql = """
        INSERT INTO packets (
            timestamp, src_ip, dst_ip, src_port, dst_port,
            protocol, length, info, is_suspicious, anomaly_score, source_type
        ) VALUES (
            :timestamp, :src_ip, :dst_ip, :src_port, :dst_port,
            :protocol, :length, :info, :is_suspicious, :anomaly_score, :source_type
        )
        """
        with get_db().get_cursor() as cursor:
            cursor.executemany(sql, packets_list)

    @staticmethod
    def get_recent_packets(limit: int = 50, source_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves the most recent packets."""
        with get_db().get_cursor() as cursor:
            if source_type:
                cursor.execute(
                    "SELECT * FROM packets WHERE source_type = ? ORDER BY id DESC LIMIT ?",
                    (source_type, limit),
                )
            else:
                cursor.execute("SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    @staticmethod
    def get_packet_stats() -> Dict[str, Any]:
        """Calculates aggregate packet and traffic statistics for the SOC dashboard."""
        with get_db().get_cursor() as cursor:
            # Total counts
            cursor.execute("SELECT COUNT(*) as total FROM packets")
            total = cursor.fetchone()["total"]

            cursor.execute("SELECT COUNT(*) as suspicious FROM packets WHERE is_suspicious = 1")
            suspicious = cursor.fetchone()["suspicious"]

            normal = total - suspicious

            # Protocol breakdown
            cursor.execute("""
                SELECT protocol, COUNT(*) as count 
                FROM packets 
                GROUP BY protocol 
                ORDER BY count DESC 
                LIMIT 8
            """)
            protocols = [dict(row) for row in cursor.fetchall()]

            # Recent traffic volume by minute/hour
            cursor.execute("""
                SELECT strftime('%H:%M', timestamp) as time_slot, COUNT(*) as count
                FROM packets
                GROUP BY time_slot
                ORDER BY timestamp DESC
                LIMIT 15
            """)
            traffic_trend = list(reversed([dict(row) for row in cursor.fetchall()]))

            return {
                "total_packets": total,
                "normal_traffic": normal,
                "suspicious_traffic": suspicious,
                "protocols": protocols,
                "traffic_trend": traffic_trend,
            }


class AlertRepository:
    """Handles security alerts and threat detections."""

    @staticmethod
    def create_alert(alert_data: Dict[str, Any]) -> str:
        """Creates a new security alert with a unique identifier."""
        if "alert_id" not in alert_data or not alert_data["alert_id"]:
            alert_data["alert_id"] = f"ALT-{uuid.uuid4().hex[:8].upper()}"

        if "timestamp" not in alert_data or not alert_data["timestamp"]:
            alert_data["timestamp"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        sql = """
        INSERT INTO alerts (
            alert_id, timestamp, src_ip, dst_ip, detection_type,
            rule_name, description, severity, risk_score, explanation, status
        ) VALUES (
            :alert_id, :timestamp, :src_ip, :dst_ip, :detection_type,
            :rule_name, :description, :severity, :risk_score, :explanation, :status
        )
        """
        alert_data.setdefault("status", "New")
        with get_db().get_cursor() as cursor:
            cursor.execute(sql, alert_data)
            return alert_data["alert_id"]

    @staticmethod
    def get_recent_alerts(limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieves recent alerts sorted newest first."""
        with get_db().get_cursor() as cursor:
            cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    @staticmethod
    def get_alert_counts() -> Dict[str, int]:
        """Returns total alerts grouped by severity level."""
        with get_db().get_cursor() as cursor:
            cursor.execute("""
                SELECT severity, COUNT(*) as count 
                FROM alerts 
                GROUP BY severity
            """)
            counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Total": 0}
            for row in cursor.fetchall():
                sev = row["severity"]
                cnt = row["count"]
                if sev in counts:
                    counts[sev] = cnt
                counts["Total"] += cnt
            return counts

    @staticmethod
    def search_incidents(
        ip: Optional[str] = None,
        severity: Optional[str] = None,
        detection_type: Optional[str] = None,
        date_from: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Searches alerts with flexible filtering for SOC incident investigation."""
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []

        if ip:
            query += " AND (src_ip LIKE ? OR dst_ip LIKE ?)"
            params.extend([f"%{ip}%", f"%{ip}%"])
        if severity and severity != "All":
            query += " AND severity = ?"
            params.append(severity)
        if detection_type and detection_type != "All":
            query += " AND detection_type = ?"
            params.append(detection_type)
        if date_from:
            query += " AND timestamp >= ?"
            params.append(date_from)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with get_db().get_cursor() as cursor:
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]


class ThreatIntelRepository:
    """Manages cached threat intelligence reports."""

    @staticmethod
    def get_cached(ip: str) -> Optional[Dict[str, Any]]:
        """Checks if threat intelligence is cached for the given IP address."""
        with get_db().get_cursor() as cursor:
            cursor.execute("SELECT * FROM threat_intel_cache WHERE ip = ?", (ip,))
            row = cursor.fetchone()
            if row:
                result = dict(row)
                if result.get("raw_data"):
                    try:
                        result["raw_data"] = json.loads(result["raw_data"])
                    except Exception:
                        pass
                return result
            return None

    @staticmethod
    def save_cache(ip: str, data: Dict[str, Any]):
        """Caches threat intelligence results for an IP address."""
        raw_str = json.dumps(data.get("raw_data", {}))
        sql = """
        INSERT INTO threat_intel_cache (
            ip, reputation_score, total_reports, country, isp, is_tor, raw_data, last_queried
        ) VALUES (
            :ip, :reputation_score, :total_reports, :country, :isp, :is_tor, :raw_data, CURRENT_TIMESTAMP
        )
        ON CONFLICT(ip) DO UPDATE SET
            reputation_score = excluded.reputation_score,
            total_reports = excluded.total_reports,
            country = excluded.country,
            isp = excluded.isp,
            is_tor = excluded.is_tor,
            raw_data = excluded.raw_data,
            last_queried = CURRENT_TIMESTAMP
        """
        payload = {
            "ip": ip,
            "reputation_score": data.get("reputation_score", 0),
            "total_reports": data.get("total_reports", 0),
            "country": data.get("country", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "is_tor": 1 if data.get("is_tor") else 0,
            "raw_data": raw_str,
        }
        with get_db().get_cursor() as cursor:
            cursor.execute(sql, payload)


class SettingsRepository:
    """Key-value settings repository."""

    @staticmethod
    def get(key: str, default: Optional[str] = None) -> Optional[str]:
        with get_db().get_cursor() as cursor:
            cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row["value"] if row else default

    @staticmethod
    def set(key: str, value: str):
        with get_db().get_cursor() as cursor:
            cursor.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

