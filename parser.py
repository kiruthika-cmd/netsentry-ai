"""
NetSentry AI - Network Packet Dissection and Parsing Engine
Extracts source/dest IPs, protocols, port numbers, flags, and payload metadata using Scapy.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Packet


class PacketParser:
    """Parses raw Scapy packets into standardized metadata dictionaries."""

    @staticmethod
    def parse(packet: Packet, source_type: str = "live") -> Optional[Dict[str, Any]]:
        """
        Extracts key security and protocol attributes from a packet.
        Handles IPv4, IPv6, ARP, TCP, UDP, ICMP, and common services.
        """
        try:
            timestamp_val = getattr(packet, "time", None)
            if timestamp_val:
                dt = datetime.fromtimestamp(float(timestamp_val), timezone.utc).replace(tzinfo=None)
                timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            else:
                timestamp_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

            length = len(packet)

            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            src_port = None
            dst_port = None
            protocol = "OTHER"
            info = ""
            tcp_flags = ""

            # Check Network Layer
            if packet.haslayer(IP):
                ip_layer = packet.getlayer(IP)
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                proto_num = ip_layer.proto
            elif packet.haslayer(IPv6):
                ipv6_layer = packet.getlayer(IPv6)
                src_ip = ipv6_layer.src
                dst_ip = ipv6_layer.dst
                proto_num = ipv6_layer.nh
            elif packet.haslayer(ARP):
                arp_layer = packet.getlayer(ARP)
                src_ip = arp_layer.psrc
                dst_ip = arp_layer.pdst
                protocol = "ARP"
                info = f"ARP Request/Reply: {arp_layer.hwsrc} -> {arp_layer.hwdst}"
                return {
                    "timestamp": timestamp_str,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": 0,
                    "dst_port": 0,
                    "protocol": protocol,
                    "length": length,
                    "info": info,
                    "tcp_flags": "",
                    "source_type": source_type,
                    "is_suspicious": 0,
                    "anomaly_score": 0.0,
                }
            else:
                return None

            # Check Transport Layer
            if packet.haslayer(TCP):
                tcp = packet.getlayer(TCP)
                src_port = int(tcp.sport)
                dst_port = int(tcp.dport)
                protocol = "TCP"
                tcp_flags = str(tcp.flags)
                info = f"TCP {src_port} -> {dst_port} [Flags: {tcp_flags}] Seq={tcp.seq}"
                
                # Identify prominent application layer protocols by port
                if dst_port == 80 or src_port == 80:
                    protocol = "HTTP"
                elif dst_port == 443 or src_port == 443:
                    protocol = "HTTPS"
                elif dst_port == 22 or src_port == 22:
                    protocol = "SSH"
                elif dst_port == 21 or src_port == 21:
                    protocol = "FTP"
                elif dst_port == 23 or src_port == 23:
                    protocol = "TELNET"
                elif dst_port == 3389 or src_port == 3389:
                    protocol = "RDP"
                elif dst_port == 445 or src_port == 445:
                    protocol = "SMB"

            elif packet.haslayer(UDP):
                udp = packet.getlayer(UDP)
                src_port = int(udp.sport)
                dst_port = int(udp.dport)
                protocol = "UDP"
                info = f"UDP {src_port} -> {dst_port} Len={udp.len}"

                if dst_port == 53 or src_port == 53:
                    protocol = "DNS"
                elif dst_port in (67, 68) or src_port in (67, 68):
                    protocol = "DHCP"
                elif dst_port == 123 or src_port == 123:
                    protocol = "NTP"
                elif dst_port == 161 or src_port == 161:
                    protocol = "SNMP"

            elif packet.haslayer(ICMP):
                icmp = packet.getlayer(ICMP)
                protocol = "ICMP"
                src_port = 0
                dst_port = 0
                info = f"ICMP Type={icmp.type} Code={icmp.code}"

            else:
                src_port = 0
                dst_port = 0
                protocol = f"IP-Proto-{proto_num}"
                info = f"IP protocol {proto_num}"

            return {
                "timestamp": timestamp_str,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port or 0,
                "dst_port": dst_port or 0,
                "protocol": protocol,
                "length": length,
                "info": info[:200],
                "tcp_flags": tcp_flags,
                "source_type": source_type,
                "is_suspicious": 0,
                "anomaly_score": 0.0,
            }
        except Exception:
            return None
