"""
CyberSentinel — Packet Parser
==============================
Extracts structured fields from raw PyShark packet objects.
Never crashes — malformed packets are logged and skipped.
"""

import logging
from datetime import datetime
from typing import Optional

from app.schemas.flow import ParsedPacket

logger = logging.getLogger("cybersentinel.packet_parser")

# Protocols we care about (mapped from IP protocol numbers)
_PROTOCOL_MAP = {
    "6": "TCP",
    "17": "UDP",
    "1": "ICMP",
    "58": "ICMP",  # ICMPv6 → treat as ICMP
}

# Protocols to silently ignore (no logging, no processing)
_IGNORED_PROTOCOLS = {"ARP", "LLDP", "STP", "CDP", "EAPOL", "LOOP"}


class PacketParser:
    """
    Parses raw PyShark packet objects into structured ParsedPacket models.

    Design decisions:
        - Every field extraction is wrapped in try/except — one bad field
          doesn't kill the entire packet or crash the capture loop.
        - ICMP packets have no ports — we set src_port=0, dst_port=0.
        - Protocol normalization uses the IP layer's protocol number, not
          the highest-layer name, for consistency with the training data.
    """

    def __init__(self):
        self._parsed_count = 0
        self._skipped_count = 0

    @property
    def stats(self) -> dict:
        return {
            "parsed": self._parsed_count,
            "skipped": self._skipped_count,
        }

    def parse(self, raw_packet) -> Optional[ParsedPacket]:
        """
        Parse a single PyShark packet into a ParsedPacket.

        Returns None if the packet should be skipped (non-IP, malformed, etc.)
        """
        try:
            # ── Must have IP layer ────────────────────────────────────────
            if not hasattr(raw_packet, "ip"):
                self._skipped_count += 1
                return None

            # ── Check for ignored protocols at highest layer ─────────────
            highest_layer = raw_packet.highest_layer
            if highest_layer in _IGNORED_PROTOCOLS:
                self._skipped_count += 1
                return None

            # ── Extract IP fields ────────────────────────────────────────
            ip_layer = raw_packet.ip
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            proto_num = str(ip_layer.proto)
            protocol = _PROTOCOL_MAP.get(proto_num, "OTHER")

            # ── Timestamp ────────────────────────────────────────────────
            raw_timestamp = raw_packet.sniff_timestamp
            try:
                timestamp = float(raw_timestamp)
            except (TypeError, ValueError):
                timestamp = datetime.fromisoformat(
                    str(raw_timestamp).replace("Z", "+00:00")
                ).timestamp()

            # ── Packet length ────────────────────────────────────────────
            packet_length = int(raw_packet.length)

            # ── Ports (protocol-dependent) ───────────────────────────────
            src_port = 0
            dst_port = 0

            if protocol == "TCP" and hasattr(raw_packet, "tcp"):
                src_port = int(raw_packet.tcp.srcport)
                dst_port = int(raw_packet.tcp.dstport)
            elif protocol == "UDP" and hasattr(raw_packet, "udp"):
                src_port = int(raw_packet.udp.srcport)
                dst_port = int(raw_packet.udp.dstport)
            # ICMP has no ports — leave as 0

            self._parsed_count += 1

            return ParsedPacket(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_length=packet_length,
            )

        except Exception as e:
            self._skipped_count += 1
            logger.debug(
                "Skipped malformed packet (%s): %s", type(e).__name__, e
            )
            return None

    def reset_stats(self):
        """Reset parse/skip counters."""
        self._parsed_count = 0
        self._skipped_count = 0
