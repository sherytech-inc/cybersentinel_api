"""Bounded, read-only parsing for supported operating-system firewall logs."""

from __future__ import annotations

import csv
import hashlib
import io
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from ipaddress import ip_address

from app.schemas.firewall_analysis import FirewallNormalizedEvent

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_LINES = 50_000
MAX_LINE_LENGTH = 16_384
MAX_EVENTS_RETURNED = 1_000
MAX_WARNING_SAMPLES = 20

_KV_PATTERN = re.compile(r"\b([A-Z][A-Z0-9_]*)=([^\s]*)")
_UFW_ACTION = re.compile(r"\[UFW\s+(ALLOW|BLOCK|DENY|DROP|REJECT|AUDIT)\]")
_SYSLOG_TIME = re.compile(r"^(?:\S+\s+)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
_PF_LINE = re.compile(
    r"(?:(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+)?"
    r"(?:rule\s+(?P<rule>[^:]+):\s+)?"
    r"(?P<action>pass|block)\s+(?P<direction>in|out)\s+on\s+(?P<interface>[\w.:-]+):\s+"
    r"(?P<src>(?:\d{1,3}\.){3}\d{1,3})(?:\.(?P<src_port>\d+))?\s+>\s+"
    r"(?P<dst>(?:\d{1,3}\.){3}\d{1,3})(?:\.(?P<dst_port>\d+))?"
    r"(?:.*?\b(?P<protocol>TCP|UDP|ICMP|ICMP6)\b)?",
    re.IGNORECASE,
)


class FirewallFormat(str, Enum):
    windows_firewall = "windows_firewall"
    ufw = "ufw"
    iptables = "iptables"
    macos_pf = "macos_pf"
    generic_csv = "generic_csv"
    unsupported = "unsupported"


@dataclass
class FirewallParseResult:
    detected_format: FirewallFormat
    total_lines: int
    events: list[FirewallNormalizedEvent] = field(default_factory=list)
    failed_lines: int = 0
    warnings: list[str] = field(default_factory=list)
    events_truncated: bool = False


def _warning(result: FirewallParseResult, line_number: int, reason: str) -> None:
    if len(result.warnings) < MAX_WARNING_SAMPLES:
        result.warnings.append(f"Line {line_number}: {reason}.")


def _safe_int(value: str | None, maximum: int | None = None) -> int | None:
    if not value or value == "-":
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    if parsed < 0 or (maximum is not None and parsed > maximum):
        return None
    return parsed


def _safe_ip(value: str | None) -> str | None:
    if not value or value == "-":
        return None
    try:
        return str(ip_address(value.strip("[]")))
    except ValueError:
        return None


def _action(value: str | None) -> str:
    normalized = (value or "").lower()
    return {
        "allow": "allow",
        "pass": "allow",
        "accept": "allow",
        "block": "deny",
        "deny": "deny",
        "drop": "drop",
        "reject": "reject",
    }.get(normalized, "unknown")


def _direction(value: str | None, incoming: str | None = None, outgoing: str | None = None) -> str:
    normalized = (value or "").lower()
    if normalized in {"in", "inbound", "receive"}:
        return "inbound"
    if normalized in {"out", "outbound", "send"}:
        return "outbound"
    if incoming and not outgoing:
        return "inbound"
    if outgoing and not incoming:
        return "outbound"
    return "unknown"


def _event_id(line_number: int, values: list[object]) -> str:
    stable = "|".join("" if value is None else str(value) for value in values)
    return hashlib.sha256(f"{line_number}|{stable}".encode()).hexdigest()[:24]


def _timestamp(value: str | None, formats: tuple[str, ...]) -> datetime | None:
    if not value or value == "-":
        return None
    for fmt in formats:
        try:
            parsed = datetime.strptime(value, fmt)
            return parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def detect_format(lines: list[str]) -> FirewallFormat:
    preview = [line.strip() for line in lines if line.strip()][:40]
    if any(line.startswith("#Fields:") for line in preview):
        return FirewallFormat.windows_firewall
    if any("[UFW " in line or "UFW=" in line for line in preview):
        return FirewallFormat.ufw
    if any("SRC=" in line and "DST=" in line and ("IN=" in line or "OUT=" in line) for line in preview):
        return FirewallFormat.iptables
    if any(_PF_LINE.search(line) for line in preview):
        return FirewallFormat.macos_pf
    if preview:
        try:
            headers = next(csv.reader([preview[0]]))
        except csv.Error:
            headers = []
        normalized = {_canonical_header(header) for header in headers}
        if {"source_ip", "destination_ip"}.issubset(normalized) and (
            "action" in normalized or "protocol" in normalized
        ):
            return FirewallFormat.generic_csv
    return FirewallFormat.unsupported


def _canonical_header(value: str) -> str:
    key = value.strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "src": "source_ip", "src_ip": "source_ip", "source": "source_ip",
        "dst": "destination_ip", "dst_ip": "destination_ip", "destination": "destination_ip",
        "src_port": "source_port", "sport": "source_port", "spt": "source_port",
        "dst_port": "destination_port", "dport": "destination_port", "dpt": "destination_port",
        "len": "packet_size", "size": "packet_size",
        "iface": "interface", "interface_name": "interface",
        "time": "timestamp", "datetime": "timestamp",
        "tcpflags": "flags",
    }
    return aliases.get(key, key)


def _append_event(result: FirewallParseResult, event: FirewallNormalizedEvent) -> None:
    result.events.append(event)
    if len(result.events) > MAX_EVENTS_RETURNED:
        result.events_truncated = True


def _status(required: list[object]) -> tuple[str, list[str]]:
    missing = sum(value is None or value == "unknown" for value in required)
    if missing:
        return "partial", ["Some fields were unavailable in this log entry."]
    return "complete", []


def _parse_windows(lines: list[str], result: FirewallParseResult) -> None:
    headers: list[str] = []
    for line_number, original in enumerate(lines, 1):
        line = original.strip()
        if line.startswith("#Fields:"):
            windows_aliases = {
                "src-ip": "source_ip",
                "dst-ip": "destination_ip",
                "src-port": "source_port",
                "dst-port": "destination_port",
                "size": "packet_size",
                "tcpflags": "flags",
                "path": "direction",
            }
            headers = [
                windows_aliases.get(item.lower(), item.lower().replace("-", "_"))
                for item in line[8:].split()
            ]
            continue
        if not line or line.startswith("#"):
            continue
        if not headers:
            result.failed_lines += 1
            _warning(result, line_number, "missing Windows #Fields header")
            continue
        parts = line.split()
        if len(parts) < len(headers):
            result.failed_lines += 1
            _warning(result, line_number, "column count does not match the header")
            continue
        row = dict(zip(headers, parts))
        src = _safe_ip(row.get("source_ip"))
        dst = _safe_ip(row.get("destination_ip"))
        action = _action(row.get("action"))
        protocol = None if row.get("protocol") in {None, "-"} else row["protocol"].lower()
        stamp = _timestamp(
            f"{row.get('date', '')} {row.get('time', '')}".strip(),
            ("%Y-%m-%d %H:%M:%S",),
        )
        status, messages = _status([action, src, dst, protocol])
        event = FirewallNormalizedEvent(
            event_id=_event_id(line_number, [stamp, action, src, dst, protocol]),
            timestamp=stamp,
            action=action,
            direction=_direction(row.get("direction")),
            interface=None if row.get("interface") in {None, "-"} else row["interface"],
            protocol=protocol,
            source_ip=src,
            destination_ip=dst,
            source_port=_safe_int(row.get("source_port"), 65535),
            destination_port=_safe_int(row.get("destination_port"), 65535),
            packet_size=_safe_int(row.get("packet_size")),
            flags=None if row.get("flags") in {None, "-"} else row["flags"],
            rule=None if row.get("rule") in {None, "-"} else row["rule"],
            raw_line_number=line_number,
            parse_status=status,
            messages=messages,
        )
        _append_event(result, event)


def _parse_linux(lines: list[str], result: FirewallParseResult, is_ufw: bool) -> None:
    for line_number, original in enumerate(lines, 1):
        line = original.strip()
        if not line:
            continue
        values = dict(_KV_PATTERN.findall(line))
        if "SRC" not in values and "DST" not in values:
            result.failed_lines += 1
            _warning(result, line_number, "not a firewall packet entry")
            continue
        marker = _UFW_ACTION.search(line)
        prefix = values.get("ACTION") or values.get("VERDICT")
        action = _action(marker.group(1) if marker else prefix)
        src = _safe_ip(values.get("SRC"))
        dst = _safe_ip(values.get("DST"))
        protocol = values.get("PROTO")
        incoming, outgoing = values.get("IN"), values.get("OUT")
        stamp_match = _SYSLOG_TIME.search(line)
        stamp = None
        if stamp_match:
            year = datetime.now(timezone.utc).year
            stamp = _timestamp(f"{year} {stamp_match.group(1)}", ("%Y %b %d %H:%M:%S",))
        status, messages = _status([action, src, dst, protocol])
        if not is_ufw and action == "unknown":
            messages.append("This iptables line did not include a deterministic verdict.")
        event = FirewallNormalizedEvent(
            event_id=_event_id(line_number, [stamp, action, src, dst, protocol]),
            timestamp=stamp,
            action=action,
            direction=_direction(None, incoming, outgoing),
            interface=incoming or outgoing or None,
            protocol=protocol.lower() if protocol else None,
            source_ip=src,
            destination_ip=dst,
            source_port=_safe_int(values.get("SPT"), 65535),
            destination_port=_safe_int(values.get("DPT"), 65535),
            packet_size=_safe_int(values.get("LEN")),
            flags=next(
                (
                    flag
                    for flag in ("SYN", "ACK", "FIN", "RST")
                    if re.search(rf"\b{flag}\b", line)
                ),
                None,
            ),
            rule=values.get("PREFIX"),
            raw_line_number=line_number,
            parse_status=status,
            messages=messages,
        )
        _append_event(result, event)


def _parse_pf(lines: list[str], result: FirewallParseResult) -> None:
    for line_number, original in enumerate(lines, 1):
        line = original.strip()
        if not line:
            continue
        match = _PF_LINE.search(line)
        if not match:
            result.failed_lines += 1
            _warning(result, line_number, "not a supported pf packet entry")
            continue
        data = match.groupdict()
        src, dst = _safe_ip(data["src"]), _safe_ip(data["dst"])
        action, protocol = _action(data["action"]), data.get("protocol")
        status, messages = _status([action, src, dst, protocol])
        stamp = _timestamp(data.get("timestamp"), ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"))
        event = FirewallNormalizedEvent(
            event_id=_event_id(line_number, [stamp, action, src, dst, protocol]),
            timestamp=stamp,
            action=action,
            direction=_direction(data.get("direction")),
            interface=data.get("interface"),
            protocol=protocol.lower() if protocol else None,
            source_ip=src,
            destination_ip=dst,
            source_port=_safe_int(data.get("src_port"), 65535),
            destination_port=_safe_int(data.get("dst_port"), 65535),
            rule=data.get("rule"),
            raw_line_number=line_number,
            parse_status=status,
            messages=messages,
        )
        _append_event(result, event)


def _parse_csv(lines: list[str], result: FirewallParseResult) -> None:
    try:
        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        if not reader.fieldnames:
            return
        for index, source_row in enumerate(reader, 2):
            row = {_canonical_header(str(key)): value for key, value in source_row.items() if key is not None}
            src, dst = _safe_ip(row.get("source_ip")), _safe_ip(row.get("destination_ip"))
            action, protocol = _action(row.get("action")), row.get("protocol") or None
            status, messages = _status([action, src, dst, protocol])
            stamp = _timestamp(
                row.get("timestamp"),
                ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"),
            )
            _append_event(result, FirewallNormalizedEvent(
                event_id=_event_id(index, [stamp, action, src, dst, protocol]),
                timestamp=stamp,
                action=action,
                direction=_direction(row.get("direction")),
                interface=row.get("interface") or None,
                protocol=protocol.lower() if protocol else None,
                source_ip=src,
                destination_ip=dst,
                source_port=_safe_int(row.get("source_port"), 65535),
                destination_port=_safe_int(row.get("destination_port"), 65535),
                packet_size=_safe_int(row.get("packet_size")),
                flags=row.get("flags") or None,
                rule=row.get("rule") or None,
                raw_line_number=index,
                parse_status=status,
                messages=messages,
            ))
    except csv.Error:
        result.failed_lines += 1
        _warning(result, 1, "invalid CSV structure")


def parse_firewall_text(text: str) -> FirewallParseResult:
    lines = text.splitlines()
    total_lines = len(lines)
    if total_lines > MAX_LINES:
        lines = lines[:MAX_LINES]
    fmt = detect_format(lines)
    result = FirewallParseResult(detected_format=fmt, total_lines=total_lines)
    if total_lines > MAX_LINES:
        result.failed_lines += total_lines - MAX_LINES
        _warning(result, MAX_LINES + 1, f"line limit of {MAX_LINES} reached")

    bounded: list[str] = []
    for line_number, line in enumerate(lines, 1):
        if len(line) > MAX_LINE_LENGTH:
            result.failed_lines += 1
            _warning(result, line_number, f"line exceeds {MAX_LINE_LENGTH} characters")
            bounded.append("")
        else:
            bounded.append(line)

    if fmt == FirewallFormat.windows_firewall:
        _parse_windows(bounded, result)
    elif fmt in {FirewallFormat.ufw, FirewallFormat.iptables}:
        _parse_linux(bounded, result, fmt == FirewallFormat.ufw)
    elif fmt == FirewallFormat.macos_pf:
        _parse_pf(bounded, result)
    elif fmt == FirewallFormat.generic_csv:
        _parse_csv(bounded, result)
    return result


def count_values(values: list[str | None], limit: int = 10) -> list[dict[str, object]]:
    counts = Counter(value for value in values if value)
    return [
        {"value": value, "count": count}
        for value, count in counts.most_common(limit)
    ]


def count_ports(values: list[int | None], limit: int = 10) -> list[dict[str, int]]:
    counts = Counter(value for value in values if value is not None)
    return [
        {"port": value, "count": count}
        for value, count in counts.most_common(limit)
    ]
