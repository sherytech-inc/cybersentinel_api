from types import SimpleNamespace

from app.services.packet_capture.packet_parser import PacketParser


def test_parser_accepts_pyshark_json_iso_timestamp():
    packet = SimpleNamespace(
        ip=SimpleNamespace(src="192.168.0.7", dst="17.248.213.67", proto="17"),
        udp=SimpleNamespace(srcport="5353", dstport="443"),
        highest_layer="DATA",
        sniff_timestamp="2026-07-20T23:17:52.269904000Z",
        length="63",
    )

    parsed = PacketParser().parse(packet)

    assert parsed is not None
    assert parsed.timestamp == 1784589472.269904
    assert parsed.protocol == "UDP"
    assert parsed.src_port == 5353
    assert parsed.dst_port == 443
