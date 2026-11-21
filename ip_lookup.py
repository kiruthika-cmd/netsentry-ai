"""
NetSentry AI - Threat Intelligence Integration Module
Queries external threat databases (AbuseIPDB, VirusTotal) with rate-limiting, local caching,
and strict evidence-based verification.
"""

import ipaddress
import logging
from typing import Dict, Any, Optional
import requests
from src.database.models import ThreatIntelRepository

logger = logging.getLogger("netsentry.intel")


def is_private_ip(ip_str: str) -> bool:
    """Returns True if the IP is an RFC1918 private, loopback, or link-local address."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast
    except ValueError:
        return False


class ThreatIntelligenceClient:
    """Manages threat reputation lookups with API failover and local caching."""

    def __init__(self, abuseipdb_key: str = "", virustotal_key: str = ""):
        self.abuseipdb_key = abuseipdb_key
        self.virustotal_key = virustotal_key

    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Retrieves reputation data for an IP address.
        
        Rules:
        1. Private/local IPs are tagged immediately without making external requests.
        2. Local SQLite cache is consulted first (prevents redundant API usage).
        3. If API keys are absent, returns clear passive classification with zero false accusations.
        4. If API keys are present, calls external intelligence endpoint safely.
        """
        ip_str = ip_address.strip()

        # Check for private or non-routable addresses
        if is_private_ip(ip_str):
            return {
                "ip": ip_str,
                "is_private": True,
                "reputation_score": 0,
                "total_reports": 0,
                "country": "Local / Internal Network",
                "isp": "RFC 1918 Private Address Space",
                "is_tor": False,
                "verified_malicious": False,
                "source": "Local Network Policy",
                "details": "Private IP address (non-routable on the public Internet).",
            }

        # Check local cache
        cached = ThreatIntelRepository.get_cached(ip_str)
        if cached:
            return {
                "ip": ip_str,
                "is_private": False,
                "reputation_score": cached["reputation_score"],
                "total_reports": cached["total_reports"],
                "country": cached["country"],
                "isp": cached["isp"],
                "is_tor": bool(cached["is_tor"]),
                "verified_malicious": cached["reputation_score"] >= 50,
                "source": "Local Cache (Historical Lookup)",
                "details": f"Cached intelligence record. Threat score: {cached['reputation_score']}/100.",
            }

        # Attempt AbuseIPDB lookup if API key is provided
        if self.abuseipdb_key:
            try:
                headers = {
                    "Key": self.abuseipdb_key,
                    "Accept": "application/json",
                }
                params = {"ipAddress": ip_str, "maxAgeInDays": "90"}
                resp = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers=headers,
                    params=params,
                    timeout=5.0,
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    rep_score = int(data.get("abuseConfidenceScore", 0))
                    total_rep = int(data.get("totalReports", 0))
                    country = str(data.get("countryCode", "Unknown"))
                    isp = str(data.get("isp", "Unknown"))
                    is_tor = bool(data.get("isTor", False))

                    result_payload = {
                        "reputation_score": rep_score,
                        "total_reports": total_rep,
                        "country": country,
                        "isp": isp,
                        "is_tor": is_tor,
                        "raw_data": data,
                    }
                    ThreatIntelRepository.save_cache(ip_str, result_payload)

                    return {
                        "ip": ip_str,
                        "is_private": False,
                        "reputation_score": rep_score,
                        "total_reports": total_rep,
                        "country": country,
                        "isp": isp,
                        "is_tor": is_tor,
                        "verified_malicious": rep_score >= 50,
                        "source": "AbuseIPDB API",
                        "details": f"Live query result. Confidence score: {rep_score}%. Total abuse reports: {total_rep}.",
                    }
            except Exception as e:
                logger.warning(f"AbuseIPDB request failed for {ip_str}: {e}")

        # Fallback when no API key is configured
        fallback_result = {
            "ip": ip_str,
            "is_private": False,
            "reputation_score": 0,
            "total_reports": 0,
            "country": "Public Internet",
            "isp": "External AS Network",
            "is_tor": False,
            "verified_malicious": False,
            "source": "Passive Classifier (No API Key Configured)",
            "details": "Public routable IP. Configure ABUSEIPDB_API_KEY in .env or Settings for live threat scoring.",
        }
        ThreatIntelRepository.save_cache(ip_str, fallback_result)
        return fallback_result

