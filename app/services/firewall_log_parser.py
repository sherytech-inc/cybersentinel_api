import re
import os
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
import pytz

from app.schemas.firewall import FirewallLogIngestRequest

class FirewallLogFormat(Enum):
    ufw = "ufw"
    windows_firewall = "windows_firewall"
    unsupported = "unsupported"
    empty = "empty"

@dataclass
class ParseResult:
    format: FirewallLogFormat
    imported: list[FirewallLogIngestRequest] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

def detect_format(lines: list[str]) -> FirewallLogFormat:
    significant = [line.strip() for line in lines if line.strip()]
    if not significant:
        return FirewallLogFormat.empty
    preview = significant[:20]
    if any(line.startswith("#Fields:") for line in preview):
        return FirewallLogFormat.windows_firewall
    if any("[UFW " in line or "UFW=" in line for line in preview):
        return FirewallLogFormat.ufw
    return FirewallLogFormat.unsupported

def parse_ufw(lines: list[str]) -> ParseResult:
    imported = []
    rejected = []
    warnings = []

    # Regex to extract key-value pairs
    kv_pattern = re.compile(r'([A-Z0-9_]+)=([^\s]*)')
    # Regex to capture date and action
    action_pattern = re.compile(r'(?P<date>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}).*?\[UFW\s+(?P<action>BLOCK|ALLOW|AUDIT)\]')

    current_year = datetime.now().year
    tz_str = os.environ.get("FIREWALL_IMPORT_TIMEZONE", "UTC")
    try:
        tz = pytz.timezone(tz_str)
    except pytz.UnknownTimeZoneError:
        tz = pytz.UTC
        warnings.append(f"Unknown timezone '{tz_str}', fell back to UTC.")

    inferred_timestamp = False

    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue

        action_match = action_pattern.search(line)
        if not action_match:
            rejected.append({"line": i + 1, "content": line[:250], "reason": "No valid UFW action found"})
            continue

        action_str = action_match.group('action').upper()
        # Normalize
        if action_str == "AUDIT":
            action_str = "ALLOW" # Simplified normalization for unsupported actions if needed

        date_str = action_match.group('date')
        
        try:
            # UFW log format: 'Jul 19 12:34:56'
            # We must append the current year
            dt_naive = datetime.strptime(f"{current_year} {date_str}", "%Y %b %d %H:%M:%S")
            dt_aware = tz.localize(dt_naive).astimezone(timezone.utc)
            inferred_timestamp = True
        except ValueError:
            dt_aware = None

        # Parse key value pairs
        kv_matches = kv_pattern.findall(line)
        kv_dict = {k: v for k, v in kv_matches}

        src_ip = kv_dict.get('SRC')
        if not src_ip:
            rejected.append({"line": i + 1, "content": line[:250], "reason": "Missing SRC IP"})
            continue

        try:
            req = FirewallLogIngestRequest(
                source_ip=src_ip,
                destination_ip=kv_dict.get('DST'),
                source_port=int(kv_dict['SPT']) if kv_dict.get('SPT') else None,
                destination_port=int(kv_dict['DPT']) if kv_dict.get('DPT') else None,
                protocol=kv_dict.get('PROTO'),
                action=action_str,
                interface=kv_dict.get('IN') or kv_dict.get('OUT'),
                logged_at=dt_aware,
                source_line_number=i + 1
            )
            imported.append(req)
        except Exception as e:
            rejected.append({"line": i + 1, "content": line[:250], "reason": f"Validation error: {str(e)}"})

    if inferred_timestamp:
        warnings.append(f"UFW timestamps did not include a year or timezone. The year {current_year} and timezone {tz_str} were inferred.")

    return ParseResult(format=FirewallLogFormat.ufw, imported=imported, rejected=rejected, warnings=warnings)


def parse_windows_csv(lines: list[str]) -> ParseResult:
    imported = []
    rejected = []
    
    headers = []
    data_start_idx = 0
    
    # Locate headers
    for i, line in enumerate(lines):
        line = line.strip()
        if line.startswith("#Fields:"):
            # Format: #Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags
            parts = line[8:].strip().split()
            headers = [h.lower() for h in parts]
            data_start_idx = i + 1
            break

    if not headers:
        # Fallback if no #Fields header
        return ParseResult(format=FirewallLogFormat.windows_firewall, rejected=[{"line": 1, "content": "", "reason": "Missing #Fields definition"}])

    for i in range(data_start_idx, len(lines)):
        line = lines[i].strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < len(headers):
            rejected.append({"line": i + 1, "content": line[:250], "reason": "Not enough columns"})
            continue

        row = dict(zip(headers, parts))
        
        src_ip = row.get('src-ip')
        if not src_ip or src_ip == '-':
            rejected.append({"line": i + 1, "content": line[:250], "reason": "Missing src-ip"})
            continue

        action = row.get('action', '').upper()
        if action == 'DROP':
            action = 'BLOCK'
        elif action not in ['ALLOW', 'BLOCK']:
            # Normalization fallback
            if action:
                rejected.append({"line": i + 1, "content": line[:250], "reason": f"Invalid action: {action}"})
                continue
            else:
                rejected.append({"line": i + 1, "content": line[:250], "reason": "Missing action"})
                continue

        # Parse datetime
        date_str = row.get('date')
        time_str = row.get('time')
        dt_aware = None
        if date_str and time_str and date_str != '-' and time_str != '-':
            try:
                dt_naive = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
                # Assume UTC or local depending on Windows config. Defaulting to UTC for simplicity.
                dt_aware = dt_naive.replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        def parse_port(val):
            if val and val != '-':
                try:
                    return int(val)
                except ValueError:
                    return None
            return None

        try:
            req = FirewallLogIngestRequest(
                source_ip=src_ip,
                destination_ip=row.get('dst-ip') if row.get('dst-ip') != '-' else None,
                source_port=parse_port(row.get('src-port')),
                destination_port=parse_port(row.get('dst-port')),
                protocol=row.get('protocol') if row.get('protocol') != '-' else None,
                action=action,
                logged_at=dt_aware,
                source_line_number=i + 1
            )
            imported.append(req)
        except Exception as e:
            rejected.append({"line": i + 1, "content": line[:250], "reason": f"Validation error: {str(e)}"})

    return ParseResult(format=FirewallLogFormat.windows_firewall, imported=imported, rejected=rejected)

def parse_firewall_log(text: str) -> ParseResult:
    lines = text.splitlines()
    fmt = detect_format(lines)
    
    if fmt == FirewallLogFormat.empty:
        return ParseResult(format=fmt)
    if fmt == FirewallLogFormat.ufw:
        return parse_ufw(lines)
    if fmt == FirewallLogFormat.windows_firewall:
        return parse_windows_csv(lines)
        
    return ParseResult(format=fmt)
