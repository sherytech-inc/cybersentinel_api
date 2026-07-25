import pytest
from app.services.firewall_log_parser import parse_firewall_log, FirewallLogFormat

def test_ufw_parser():
    log_data = """
Jul 19 12:34:56 hostname kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=10.0.0.5 DST=192.168.1.1 LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID=12345 PROTO=TCP SPT=12345 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0
Jul 19 12:35:00 hostname kernel: [12345.678902] [UFW ALLOW] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=10.0.0.6 DST=192.168.1.1 LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID=12345 PROTO=UDP SPT=12345 DPT=53
    """
    result = parse_firewall_log(log_data)
    assert result.format == FirewallLogFormat.ufw
    assert len(result.imported) == 2
    assert len(result.rejected) == 0
    assert result.imported[0].source_ip == "10.0.0.5"
    assert result.imported[0].action == "BLOCK"
    assert result.imported[0].source_port == 12345
    assert result.imported[0].destination_port == 80
    assert result.imported[0].protocol == "TCP"
    assert result.imported[1].source_ip == "10.0.0.6"
    assert result.imported[1].action == "ALLOW"
    assert result.imported[1].protocol == "UDP"

def test_windows_defender_parser():
    log_data = """
#Software: Microsoft Windows Firewall
#Version: 1.5
#Format: 1.0
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path
2026-07-19 12:34:56 DROP TCP 10.0.0.5 192.168.1.1 12345 80 40 S 1234567890 0 65535 - - - RECEIVE
2026-07-19 12:35:00 ALLOW UDP 10.0.0.6 192.168.1.1 12345 53 40 - - - - - - - RECEIVE
    """
    result = parse_firewall_log(log_data)
    assert result.format == FirewallLogFormat.windows_firewall
    assert len(result.imported) == 2
    assert len(result.rejected) == 0
    assert result.imported[0].source_ip == "10.0.0.5"
    assert result.imported[0].action == "BLOCK"  # Normalized to BLOCK
    assert result.imported[0].source_port == 12345
    assert result.imported[0].destination_port == 80
    assert result.imported[0].protocol == "TCP"
    assert result.imported[1].source_ip == "10.0.0.6"
    assert result.imported[1].action == "ALLOW"
    assert result.imported[1].protocol == "UDP"

def test_unsupported_format():
    log_data = """
This is some random log file that is not UFW or Windows Defender.
It has some random text.
    """
    result = parse_firewall_log(log_data)
    assert result.format == FirewallLogFormat.unsupported

def test_empty_format():
    log_data = "   \n\n  "
    result = parse_firewall_log(log_data)
    assert result.format == FirewallLogFormat.empty

def test_rejected_lines():
    log_data = """
Jul 19 12:34:56 hostname kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd DST=192.168.1.1 LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID=12345 PROTO=TCP SPT=12345 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0
    """ # Missing SRC
    result = parse_firewall_log(log_data)
    assert result.format == FirewallLogFormat.ufw
    assert len(result.imported) == 0
    assert len(result.rejected) == 1
    assert "Missing SRC IP" in result.rejected[0]['reason']

