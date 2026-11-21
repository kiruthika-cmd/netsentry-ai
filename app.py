"""
NetSentry AI - Main Flask Application
Orchestrates passive network monitoring, offline PCAP analysis, AI anomaly detection,
rule-based threat signatures, and the SOC analyst dashboard.
"""

import os
import logging
from pathlib import Path
from flask import (
    Flask, render_template, request, jsonify, redirect, url_for, Response
)
from werkzeug.utils import secure_filename
from scapy.all import rdpcap

from config import get_config
from src.database.db import init_database
from src.database.models import (
    PacketRepository, AlertRepository, SettingsRepository, ThreatIntelRepository
)
from src.analysis.parser import PacketParser
from src.analysis.validator import validate_pcap_file, FileValidationError
from src.ml.model import get_detector
from src.ml.baseline_data import ensure_model_trained
from src.detection.rules import ThreatDetectionEngine
from src.detection.risk_scorer import calculate_risk_score
from src.monitoring.sniffer import get_sniffer
from src.intelligence.ip_lookup import ThreatIntelligenceClient
from src.reporting.exporter import (
    export_alerts_to_csv, export_packets_to_csv, generate_incident_summary_report
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netsentry.app")

# Initialize Flask app
config = get_config()
app = Flask(__name__)
app.config.from_object(config)

# Ensure required directories exist
config.UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
config.SAMPLE_FOLDER.mkdir(parents=True, exist_ok=True)

# Initialize Database and Machine Learning Engine
db_manager = init_database(config.DATABASE_PATH)
ensure_model_trained(config.MODEL_PATH, config.FEATURE_SCALER_PATH)

# Initialize Threat Detection Engine and Intel Client
rule_engine = ThreatDetectionEngine()
intel_client = ThreatIntelligenceClient(
    abuseipdb_key=config.ABUSEIPDB_API_KEY,
    virustotal_key=config.VIRUSTOTAL_API_KEY
)


def handle_incoming_packet(parsed_packet: dict):
    """
    Central pipeline processing every network packet (live or PCAP):
    1. Scores packet with Isolation Forest ML model.
    2. Evaluates packet against deterministic threat rules.
    3. Triggers explainable alerts for rule hits or significant ML anomalies.
    4. Commits packet to SQLite database.
    """
    try:
        detector = get_detector()
        # ML Anomaly inference
        detector.score_packets([parsed_packet])

        # Rule-based inspection
        rule_alerts = rule_engine.inspect_packet(parsed_packet)
        for alt in rule_alerts:
            AlertRepository.create_alert(alt)
            parsed_packet["is_suspicious"] = 1

        # Check for unclassified pure ML statistical anomaly
        threshold = float(SettingsRepository.get("anomaly_threshold", "-0.15"))
        if parsed_packet.get("anomaly_score", 0.0) < threshold and not rule_alerts:
            parsed_packet["is_suspicious"] = 1
            risk_info = calculate_risk_score(
                base_severity="Medium",
                factors={
                    "rule_triggered": "Unsupervised Statistical Anomaly",
                    "target_ip": parsed_packet["dst_ip"],
                },
                anomaly_score=parsed_packet["anomaly_score"],
            )
            AlertRepository.create_alert({
                "src_ip": parsed_packet["src_ip"],
                "dst_ip": parsed_packet["dst_ip"],
                "detection_type": "ml",
                "rule_name": "ML_ANOMALY_ISOLATION_FOREST",
                "description": f"Statistical anomaly detected by Isolation Forest (Decision score: {parsed_packet['anomaly_score']:.3f}).",
                "severity": risk_info["severity"],
                "risk_score": risk_info["score"],
                "explanation": risk_info["explanation"],
            })

        # Save packet record
        PacketRepository.insert_packet(parsed_packet)
    except Exception as e:
        logger.error(f"Error handling packet: {e}", exc_info=True)


# Initialize Sniffer with packet callback
sniffer = get_sniffer(callback=handle_incoming_packet)


# -------------------------------------------------------------
# Frontend Page Routes
# -------------------------------------------------------------

@app.route("/")
def dashboard():
    """Module 1: SOC Executive Dashboard."""
    metrics = PacketRepository.get_packet_stats()
    alert_counts = AlertRepository.get_alert_counts()
    recent_alerts = AlertRepository.get_recent_alerts(limit=10)
    return render_template(
        "dashboard.html",
        metrics=metrics,
        alert_counts=alert_counts,
        recent_alerts=recent_alerts
    )


@app.route("/monitoring")
def monitoring():
    """Module 2: Live Network Packet Monitoring View."""
    return render_template("monitoring.html")


@app.route("/pcap")
def pcap_analysis():
    """Module 3: PCAP / PCAPNG File Upload and Offline Inspection View."""
    return render_template("pcap.html")


@app.route("/pcap/upload", methods=["POST"])
def upload_pcap():
    """Secure PCAP File Upload Handler."""
    if "pcap_file" not in request.files:
        return render_template("pcap.html", error_msg="No file part in upload request.")

    file = request.files["pcap_file"]
    if not file or file.filename == "":
        return render_template("pcap.html", error_msg="No file was selected.")

    filename = secure_filename(file.filename)
    save_path = config.UPLOAD_FOLDER / filename

    try:
        file.save(save_path)
        # Security validation (size, extension, magic bytes)
        validate_pcap_file(save_path, max_size_bytes=config.MAX_CONTENT_LENGTH)

        # Dissect PCAP with Scapy
        raw_packets = rdpcap(str(save_path))
        parsed_list = []
        suspicious_count = 0
        detector = get_detector()

        for raw_pkt in raw_packets:
            parsed = PacketParser.parse(raw_pkt, source_type="pcap")
            if parsed:
                # Score and evaluate each packet
                detector.score_packets([parsed])
                rule_alerts = rule_engine.inspect_packet(parsed)
                for alt in rule_alerts:
                    AlertRepository.create_alert(alt)
                    parsed["is_suspicious"] = 1

                if parsed["is_suspicious"] or parsed.get("anomaly_score", 0) < -0.15:
                    suspicious_count += 1

                parsed_list.append(parsed)

        # Batch insert into database
        PacketRepository.insert_packets_bulk(parsed_list)

        return render_template(
            "pcap.html",
            success_msg=f"Successfully analyzed {len(parsed_list):,} packets from '{filename}'.",
            pcap_packets=parsed_list[:100],  # Render top 100 in table
            pcap_suspicious_count=suspicious_count,
            pcap_alerts_count=suspicious_count,
        )
    except FileValidationError as ve:
        return render_template("pcap.html", error_msg=str(ve))
    except Exception as ex:
        logger.error(f"PCAP processing failed: {ex}", exc_info=True)
        return render_template(
            "pcap.html",
            error_msg=f"Failed to process capture file: {str(ex)}"
        )
    finally:
        # Clean up temporary upload file
        if save_path.exists():
            try:
                save_path.unlink()
            except Exception:
                pass


@app.route("/alerts")
def alerts_view():
    """Module 4 & 5: Threat Detection & Security Alerts."""
    alerts = AlertRepository.get_recent_alerts(limit=100)
    return render_template("alerts.html", alerts=alerts)


@app.route("/incidents")
def incidents_view():
    """Module 8: Incident Investigation Workbench."""
    ip = request.args.get("ip", "").strip()
    sev = request.args.get("severity", "All")
    det_type = request.args.get("detection_type", "All")

    incidents = AlertRepository.search_incidents(
        ip=ip if ip else None,
        severity=sev,
        detection_type=det_type,
        limit=100
    )
    return render_template(
        "incidents.html",
        incidents=incidents,
        search_ip=ip,
        selected_severity=sev,
        selected_type=det_type
    )


@app.route("/reports")
def reports_view():
    """Module 8: Incident Reporting and Summary."""
    metrics = PacketRepository.get_packet_stats()
    alert_counts = AlertRepository.get_alert_counts()
    recent_alerts = AlertRepository.get_recent_alerts(limit=15)
    summary_report = generate_incident_summary_report(
        metrics, recent_alerts, alert_counts
    )
    return render_template("reports.html", summary_report=summary_report)


@app.route("/settings", methods=["GET", "POST"])
def settings_view():
    """Module 6 & Settings: Threat Intelligence API and Thresholds."""
    saved_msg = None
    if request.method == "POST":
        abuse_key = request.form.get("abuseipdb_key", "").strip()
        threshold = request.form.get("anomaly_threshold", "-0.15").strip()

        SettingsRepository.set("abuseipdb_key", abuse_key)
        SettingsRepository.set("anomaly_threshold", threshold)

        # Update running client key
        intel_client.abuseipdb_key = abuse_key
        saved_msg = "Settings saved successfully."

    current_abuse_key = SettingsRepository.get("abuseipdb_key", config.ABUSEIPDB_API_KEY)
    current_threshold = SettingsRepository.get("anomaly_threshold", "-0.15")

    return render_template(
        "settings.html",
        abuseipdb_key=current_abuse_key,
        anomaly_threshold=current_threshold,
        saved_msg=saved_msg
    )


# -------------------------------------------------------------
# REST API Endpoints
# -------------------------------------------------------------

@app.route("/api/stats")
def api_stats():
    """Returns real-time metrics for SOC charts and KPI counters."""
    metrics = PacketRepository.get_packet_stats()
    metrics["alert_counts"] = AlertRepository.get_alert_counts()
    metrics["monitoring_active"] = sniffer.is_running
    metrics["simulated_mode"] = getattr(sniffer, "simulated_mode", False)
    return jsonify(metrics)


@app.route("/api/monitoring/status")
def api_monitoring_status():
    """Returns active sniffer status."""
    return jsonify({
        "is_running": sniffer.is_running,
        "simulated_mode": getattr(sniffer, "simulated_mode", False),
        "packet_count": sniffer.packet_count,
    })


@app.route("/api/monitoring/start", methods=["POST"])
def api_monitoring_start():
    """Starts live packet capture."""
    payload = request.get_json(silent=True) or {}
    iface = payload.get("interface", "default")
    sniffer.start(interface=iface)
    return jsonify({
        "status": "success",
        "message": "Monitoring initiated.",
        "simulated_mode": sniffer.simulated_mode,
    })


@app.route("/api/monitoring/stop", methods=["POST"])
def api_monitoring_stop():
    """Stops live packet capture."""
    sniffer.stop()
    return jsonify({"status": "success", "message": "Monitoring stopped."})


@app.route("/api/monitoring/packets")
def api_monitoring_packets():
    """Fetches recent packets for live streaming table."""
    limit = int(request.args.get("limit", 25))
    packets = PacketRepository.get_recent_packets(limit=limit)
    return jsonify(packets)


@app.route("/api/intel/lookup/<ip>")
def api_intel_lookup(ip):
    """Module 6: Threat Intelligence reputation query."""
    result = intel_client.check_ip(ip)
    return jsonify(result)


@app.route("/export/alerts/csv")
def export_alerts_csv():
    """Module 8: Export alerts to CSV file."""
    alerts = AlertRepository.get_recent_alerts(limit=5000)
    csv_data = export_alerts_to_csv(alerts)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=netsentry_alerts.csv"}
    )


@app.route("/export/packets/csv")
def export_packets_csv():
    """Module 8: Export packets to CSV file."""
    packets = PacketRepository.get_recent_packets(limit=5000)
    csv_data = export_packets_to_csv(packets)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=netsentry_packets.csv"}
    )


if __name__ == "__main__":
    logger.info(f"Starting {config.PROJECT_NAME} SOC Platform on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)

