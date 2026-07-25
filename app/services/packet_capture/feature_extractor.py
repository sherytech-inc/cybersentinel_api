"""
CyberSentinel — Feature Extractor
===================================
Converts finalized flows into the EXACT feature schema required by
Model 1 (Random Forest) and Model 2 (Isolation Forest).

Feature names verified against:
    - Model 2 FEATURE_COLUMNS in encoder.py (explicit)
    - Model 1 RobustScaler n_features_in_=14 (shape-verified)
    - Live test: both models accept this schema ✅

WARNING: Do NOT rename or reorder these features without retraining models.
"""

import ipaddress
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Optional

import numpy as np

from app.schemas.features import ExtractedFeatures, FeatureExtractionResult

logger = logging.getLogger("cybersentinel.feature_extractor")

# RFC 1918 + link-local + loopback — anything NOT in these ranges is external
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/reserved."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def detect_external_ip(src_ip: str, dst_ip: str) -> tuple[Optional[str], bool]:
    """
    Detect the external IP in a flow.

    Returns:
        (external_ip, is_internal_only)
        - If both private: (None, True)
        - If one external: (external_ip, False)
        - If both external: (dst_ip, False) — prefer dst as the target
    """
    src_private = is_private_ip(src_ip)
    dst_private = is_private_ip(dst_ip)

    if src_private and dst_private:
        return None, True
    elif src_private and not dst_private:
        return dst_ip, False
    elif not src_private and dst_private:
        return src_ip, False
    else:
        # Both external — prefer destination as the "target"
        return dst_ip, False


class FeatureExtractor:
    """
    Converts finalized flow state dicts into model-ready feature vectors.

    The output features dict can be passed directly to:
        ensemble.evaluate_packet(features)
    without any further transformation.
    """

    def __init__(self, max_recent: int = 50):
        self._recent: deque[FeatureExtractionResult] = deque(maxlen=max_recent)
        self._extracted_count = 0
        self._failed_count = 0

    @property
    def stats(self) -> dict:
        return {
            "extracted": self._extracted_count,
            "failed": self._failed_count,
            "recent_buffer_size": len(self._recent),
        }

    def get_recent(self, limit: int = 20) -> list[FeatureExtractionResult]:
        """Return the most recent extracted features."""
        items = list(self._recent)
        items.reverse()  # newest first
        return items[:limit]

    def extract(self, flow_state: dict) -> Optional[FeatureExtractionResult]:
        """
        Extract features from a finalized flow state dict.

        Expected flow_state keys:
            src_ip, dst_ip, src_port, dst_port, protocol,
            first_packet_time, last_packet_time,
            fwd_packet_lengths, bwd_packet_lengths,
            all_packet_lengths, inter_arrival_times,
            destination_port

        Returns FeatureExtractionResult or None if validation fails.
        """
        try:
            return self._extract_impl(flow_state)
        except Exception as e:
            self._failed_count += 1
            logger.error("Feature extraction failed for flow %s: %s",
                         flow_state.get("flow_id", "unknown"), e)
            return None

    def _extract_impl(self, fs: dict) -> Optional[FeatureExtractionResult]:
        """Internal extraction logic — raises on errors."""
        src_ip = fs["src_ip"]
        dst_ip = fs["dst_ip"]
        protocol = fs["protocol"]
        flow_id = fs.get("flow_id", f"{src_ip}-{dst_ip}-{protocol}")

        # ── Validate required fields ─────────────────────────────────────
        if not src_ip or not dst_ip:
            logger.warning("Flow %s missing IPs — skipping", flow_id)
            self._failed_count += 1
            return None

        if protocol not in ("TCP", "UDP", "ICMP", "OTHER"):
            logger.warning("Flow %s has invalid protocol '%s' — skipping",
                           flow_id, protocol)
            self._failed_count += 1
            return None

        # ── Time-based features ──────────────────────────────────────────
        first_time = fs["first_packet_time"]
        last_time = fs["last_packet_time"]
        flow_duration = max(last_time - first_time, 0.001)  # floor at 1ms

        if flow_duration < 0:
            logger.warning("Flow %s has negative duration — skipping", flow_id)
            self._failed_count += 1
            return None

        # ── Packet count features ────────────────────────────────────────
        fwd_lengths = fs.get("fwd_packet_lengths", [])
        bwd_lengths = fs.get("bwd_packet_lengths", [])
        total_fwd_packets = len(fwd_lengths)
        total_backward_packets = len(bwd_lengths)
        total_packets = total_fwd_packets + total_backward_packets

        if total_packets == 0:
            logger.warning("Flow %s has zero packets — skipping", flow_id)
            self._failed_count += 1
            return None

        # ── Byte count features ──────────────────────────────────────────
        fwd_bytes = sum(fwd_lengths)
        bwd_bytes = sum(bwd_lengths)
        total_bytes = fwd_bytes + bwd_bytes

        if total_bytes < 0:
            logger.warning("Flow %s has negative bytes — skipping", flow_id)
            self._failed_count += 1
            return None

        # ── Rate features ────────────────────────────────────────────────
        # Deprecated: flow_bytes_per_second = total_bytes / flow_duration
        # Deprecated: flow_packets_per_second = total_packets / flow_duration

        # ── Packet length statistics ─────────────────────────────────────
        all_lengths = fs.get("all_packet_lengths", fwd_lengths + bwd_lengths)
        if len(all_lengths) > 0:
            arr = np.array(all_lengths, dtype=np.float64)
            pkt_len_mean = float(np.mean(arr))
            pkt_len_std = float(np.std(arr)) if len(arr) > 1 else 0.0
        else:
            pkt_len_mean = 0.0
            pkt_len_std = 0.0

        # ── Inter-arrival time statistics ────────────────────────────────
        iats = fs.get("inter_arrival_times", [])
        if len(iats) > 0:
            iat_arr = np.array(iats, dtype=np.float64)
            iat_mean = float(np.mean(iat_arr))
            iat_std = float(np.std(iat_arr)) if len(iat_arr) > 1 else 0.0
        else:
            iat_mean = 0.0
            iat_std = 0.0

        # ── Source port ─────────────────────────────────────────────
        src_port = fs.get("src_port", 0)

        # ── External IP detection ────────────────────────────────────────
        external_ip, is_internal_only = detect_external_ip(src_ip, dst_ip)

        # ── Build validated feature object ───────────────────────────────
        features = ExtractedFeatures(
            flow_duration=round(flow_duration, 6),
            src_pkts=total_fwd_packets,
            dst_pkts=total_backward_packets,
            src_bytes=fwd_bytes,
            dst_bytes=bwd_bytes,
            pkt_len_mean=round(pkt_len_mean, 4),
            pkt_len_std=round(pkt_len_std, 4),
            iat_mean=round(iat_mean, 6),
            iat_std=round(iat_std, 6),
            src_port=src_port,
            protocol=protocol,
        )

        result = FeatureExtractionResult(
            flow_id=flow_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            external_ip=external_ip,
            is_internal_only=is_internal_only,
            extracted_at=datetime.now(timezone.utc).isoformat(),
            features=features,
        )

        self._recent.append(result)
        self._extracted_count += 1

        logger.info(
            "Features extracted | flow=%s proto=%s duration=%.3fs pkts=%d ext_ip=%s",
            flow_id, protocol, flow_duration, total_packets,
            external_ip or "none (internal)",
        )

        return result
