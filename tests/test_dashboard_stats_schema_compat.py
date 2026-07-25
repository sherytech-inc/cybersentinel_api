from types import SimpleNamespace

import pytest

from app.database import client as db_client
from app.repositories.repositories import PacketRepository
from app.services.threat_response.stats_service import get_full_dashboard_stats


class _PacketQuery:
    def __init__(self):
        self.calls = 0

    def select(self, *args, **kwargs):
        return self

    def eq(self, *args, **kwargs):
        return self

    def gte(self, *args, **kwargs):
        return self

    async def execute(self):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("column packets.is_demo does not exist")
        return SimpleNamespace(
            data=[{"severity": "Normal"}, {"severity": "Suspicious"}]
        )


class _Database:
    def __init__(self, query):
        self.query = query

    def table(self, name):
        assert name == "packets"
        return self.query


@pytest.mark.asyncio
async def test_packet_stats_retry_without_optional_demo_column():
    db_client.has_demo_columns = True
    query = _PacketQuery()

    stats = await PacketRepository(_Database(query)).get_stats()

    assert query.calls == 2
    assert db_client.db_has_demo_columns() is False
    assert stats["Normal"] == 1
    assert stats["Suspicious"] == 1


@pytest.mark.asyncio
async def test_dashboard_returns_partial_stats_when_optional_metrics_fail():
    class Packets:
        async def get_stats(self):
            return {"Normal": 7, "Suspicious": 2, "Malicious": 1}

    class Alerts:
        async def get_all(self, page_size):
            raise RuntimeError("optional alerts unavailable")

    class Analytics:
        async def _count_active_threats(self):
            raise RuntimeError("optional active count unavailable")

        async def _count_currently_blocked_ips(self):
            return 3

        async def get_kpis(self, time_range):
            raise RuntimeError("optional KPI unavailable")

    stats = await get_full_dashboard_stats(
        packet_repo=Packets(), alert_repo=Alerts(), analytics=Analytics()
    )

    assert stats["total_packets_count"] == 10
    assert stats["packet_classification"] == {
        "normal": 7,
        "suspicious": 2,
        "malicious": 1,
    }
    assert stats["snapshot"]["active_threats"] == 0
    assert stats["snapshot"]["currently_blocked_ips"] == 3
    assert stats["period"]["total_threats"] == 0
