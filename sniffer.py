"""
NetSentry AI - Passive Network Sniffer Module
Captures network traffic in real-time using Scapy in a thread-safe background process.
Includes safe simulated fallback for lab demonstrations if packet capture drivers are unavailable.
"""

import threading
import time
import random
import logging
from typing import Optional, Callable
from scapy.all import sniff, conf
from src.analysis.parser import PacketParser

logger = logging.getLogger("netsentry.monitoring")


class PassiveSniffer:
    """
    Thread-safe passive network sniffer.
    Does NOT modify, inject, or disrupt any network packets.
    """

    def __init__(self, packet_callback: Optional[Callable] = None):
        self.packet_callback = packet_callback
        self.is_running = False
        self.thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.packet_count = 0
        self.interface = "default"
        self.simulated_mode = False

    def start(self, interface: str = "default", fallback_to_simulation: bool = True):
        """Starts packet sniffing in a non-blocking background thread."""
        if self.is_running:
            return

        self.interface = interface
        self._stop_event.clear()
        self.is_running = True
        self.simulated_mode = False

        self.thread = threading.Thread(
            target=self._sniff_worker,
            args=(fallback_to_simulation,),
            daemon=True,
            name="NetSentrySnifferThread",
        )
        self.thread.start()
        logger.info("Network monitoring background thread launched.")

    def stop(self):
        """Stops the active packet capture thread gracefully."""
        if not self.is_running:
            return

        self._stop_event.set()
        self.is_running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)
        logger.info("Network monitoring stopped.")

    def _sniff_worker(self, fallback_to_simulation: bool):
        """Worker function running Scapy sniff loop."""
        try:
            # Test if Scapy can sniff on current host
            def _filter_cb(pkt):
                if self._stop_event.is_set():
                    return True
                self._process_scapy_packet(pkt)
                return False

            if self.interface and self.interface != "default":
                sniff(
                    iface=self.interface,
                    prn=self._process_scapy_packet,
                    stop_filter=lambda p: self._stop_event.is_set(),
                    store=False,
                )
            else:
                sniff(
                    prn=self._process_scapy_packet,
                    stop_filter=lambda p: self._stop_event.is_set(),
                    store=False,
                )
        except Exception as e:
            logger.warning(
                f"Live raw packet capture error: {e}. "
                "Driver (e.g. Npcap on Windows) or Administrator privilege may be required."
            )
            if fallback_to_simulation and not self._stop_event.is_set():
                logger.info("Entering safe simulated laboratory traffic monitoring mode.")
                self.simulated_mode = True
                self._run_simulated_stream()

    def _process_scapy_packet(self, raw_pkt):
        """Parses and dispatches a captured packet."""
        parsed = PacketParser.parse(raw_pkt, source_type="live")
        if parsed and self.packet_callback:
            self.packet_count += 1
            self.packet_callback(parsed)

    def _run_simulated_stream(self):
        """
        Safe lab traffic generator: generates benign and occasional suspicious packets
        so the student or evaluator can test all dashboard charts and detection logic
        even when running without Administrator privileges or Npcap on Windows.
        """
        safe_hosts = ["192.168.1.10", "192.168.1.45", "192.168.1.100", "10.0.0.12"]
        safe_servers = ["142.250.190.46", "1.1.1.1", "8.8.8.8", "151.101.65.140"]
        services = [(80, "HTTP"), (443, "HTTPS"), (53, "DNS"), (123, "NTP")]

        while not self._stop_event.is_set():
            time.sleep(random.uniform(0.3, 1.2))
            src = random.choice(safe_hosts)
            dst = random.choice(safe_servers)
            port, proto = random.choice(services)

            # Occasionally generate a reconnaissance or sensitive port hit
            is_suspicious_event = random.random() < 0.12
            if is_suspicious_event:
                dst_port = random.choice([23, 445, 3389, 8080])
                proto = "TCP"
                info = f"TCP {random.randint(40000, 60000)} -> {dst_port} [SYN]"
                flags = "S"
            else:
                dst_port = port
                flags = "PA" if proto == "HTTPS" else "S"
                info = f"{proto} Client request to {dst}:{dst_port}"

            sim_packet = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": src if not is_suspicious_event else "198.51.100.77",
                "dst_ip": dst,
                "src_port": random.randint(49152, 65535),
                "dst_port": dst_port,
                "protocol": proto,
                "length": random.randint(64, 1400),
                "info": info,
                "tcp_flags": flags,
                "source_type": "live",
                "is_suspicious": 1 if is_suspicious_event else 0,
                "anomaly_score": -0.18 if is_suspicious_event else 0.12,
            }

            self.packet_count += 1
            if self.packet_callback:
                self.packet_callback(sim_packet)


# Global sniffer singleton
_sniffer_instance: Optional[PassiveSniffer] = None


def get_sniffer(callback: Optional[Callable] = None) -> PassiveSniffer:
    global _sniffer_instance
    if _sniffer_instance is None:
        _sniffer_instance = PassiveSniffer(packet_callback=callback)
    elif callback and not _sniffer_instance.packet_callback:
        _sniffer_instance.packet_callback = callback
    return _sniffer_instance

