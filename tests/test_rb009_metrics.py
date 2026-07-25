"""
RB-009 Metrics Consistency — Comprehensive Verification
=========================================================

Tests that:
1. AnalyticsService aggregation is correct across 24h, 7d, 30d ranges.
2. Dashboard /api/v1/dashboard/stats returns the same values as
   Reports /api/v1/reporting/dashboard for the same time range.
3. 24h != 7d when records exist outside the 24-hour window.
4. Blocked-IP reconstruction is deterministic under edge cases:
   - BLOCK → BLOCK → UNBLOCK → BLOCK = blocked
   - UNBLOCK without prior BLOCK = not blocked (no negative count)
   - BLOCK IP-A, BLOCK IP-B, UNBLOCK IP-A = 1 currently blocked
"""
import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.database.client import get_db_client, init_db
from app.services.reporting.analytics_service import AnalyticsService


def _utc_now():
    return datetime.now(timezone.utc)


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


async def _clean_tables(db):
    """Delete all rows from the three tables used in metrics."""
    empty_uuid = "00000000-0000-0000-0000-000000000000"
    await db.table("threat_alerts").delete().neq("alert_id", empty_uuid).execute()
    await db.table("firewall_actions").delete().neq("id", empty_uuid).execute()
    await db.table("audit_logs").delete().neq("id", empty_uuid).execute()


async def _seed_core_data(db, now):
    """Seed a deterministic dataset across 24h / 7d / 30d boundaries."""
    # ── Threat Alerts ────────────────────────────────────────────
    # 2 within 24h (1 CRITICAL OPEN, 1 HIGH INVESTIGATING)
    await db.table("threat_alerts").insert({
        "source_ip": "1.1.1.1", "severity": "CRITICAL", "status": "OPEN",
        "action": "NONE", "threat_score": 90, "summary": "Test24h-1",
        "explanation": "Test", "created_at": (now - timedelta(hours=2)).isoformat()
    }).execute()
    await db.table("threat_alerts").insert({
        "source_ip": "2.2.2.2", "severity": "HIGH", "status": "INVESTIGATING",
        "action": "NONE", "threat_score": 70, "summary": "Test24h-2",
        "explanation": "Test", "created_at": (now - timedelta(hours=5)).isoformat()
    }).execute()

    # 1 within 7d only (CRITICAL RESOLVED — not active)
    await db.table("threat_alerts").insert({
        "source_ip": "3.3.3.3", "severity": "CRITICAL", "status": "RESOLVED",
        "action": "NONE", "threat_score": 80, "summary": "Test7d",
        "explanation": "Test", "created_at": (now - timedelta(days=3)).isoformat()
    }).execute()

    # 1 within 30d only (HIGH FALSE_POSITIVE — not active)
    await db.table("threat_alerts").insert({
        "source_ip": "4.4.4.4", "severity": "HIGH", "status": "FALSE_POSITIVE",
        "action": "NONE", "threat_score": 10, "summary": "Test30d",
        "explanation": "Test", "created_at": (now - timedelta(days=15)).isoformat()
    }).execute()

    # ── Firewall Actions ─────────────────────────────────────────
    # 24h: 1 BLOCK
    await db.table("firewall_actions").insert({
        "ip": "1.1.1.1", "action": "BLOCK",
        "created_at": (now - timedelta(hours=1)).isoformat()
    }).execute()

    # 7d: 1 UNBLOCK (different IP — never blocked before → still no active block)
    await db.table("firewall_actions").insert({
        "ip": "2.2.2.2", "action": "UNBLOCK",
        "created_at": (now - timedelta(days=4)).isoformat()
    }).execute()

    # ── Audit Logs (RESOLVE / IGNORE) ────────────────────────────
    # 24h: 1 RESOLVE
    await db.table("audit_logs").insert({
        "action": "RESOLVE", "resource": "RESPONSE", "ip_address": "5.5.5.5",
        "created_at": (now - timedelta(hours=12)).isoformat()
    }).execute()

    # 7d: 1 IGNORE
    await db.table("audit_logs").insert({
        "action": "IGNORE", "resource": "RESPONSE", "ip_address": "6.6.6.6",
        "created_at": (now - timedelta(days=5)).isoformat()
    }).execute()


# ═══════════════════════════════════════════════════════════════════
# TEST 1: Cross-endpoint equality and time-range differentiation
# ═══════════════════════════════════════════════════════════════════
@pytest.mark.asyncio
async def test_rb009_cross_endpoint_consistency():
    """Dashboard period.* must equal Reports 24h KPIs, and 24h != 7d."""
    await init_db()
    db = await get_db_client()
    now = _utc_now()

    await _clean_tables(db)
    await _seed_core_data(db, now)

    analytics = AnalyticsService(db)

    # ── AnalyticsService direct verification ──────────────────────
    kpis_24h = await analytics.get_kpis("24h")
    kpis_7d = await analytics.get_kpis("7d")
    kpis_30d = await analytics.get_kpis("30d")

    # 24h counts
    assert kpis_24h["total_threats"] == 2
    assert kpis_24h["critical_threats"] == 1
    assert kpis_24h["recorded_blocks"] == 1
    assert kpis_24h["response_actions"] == 2  # 1 BLOCK + 1 RESOLVE

    # 7d counts (superset of 24h)
    assert kpis_7d["total_threats"] == 3
    assert kpis_7d["critical_threats"] == 2
    assert kpis_7d["recorded_blocks"] == 1
    assert kpis_7d["response_actions"] == 4  # 1 BLOCK + 1 UNBLOCK + 1 RESOLVE + 1 IGNORE

    # 30d counts (superset of 7d)
    assert kpis_30d["total_threats"] == 4

    # 24h != 7d (critical differentiation check)
    assert kpis_24h["total_threats"] != kpis_7d["total_threats"], \
        "24h and 7d must differ when records exist outside the 24h window"
    assert kpis_24h["response_actions"] != kpis_7d["response_actions"]

    # Snapshot metrics (time-independent)
    active = await analytics._count_active_threats()
    assert active == 2  # OPEN + INVESTIGATING

    currently_blocked = await analytics._count_currently_blocked_ips()
    assert currently_blocked == 1  # 1.1.1.1 is blocked, 2.2.2.2 UNBLOCK has no prior BLOCK

    # ── Dashboard endpoint verification ───────────────────────────
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        dash_resp = await client.get("/api/v1/dashboard/stats")
        assert dash_resp.status_code == 200
        dash = dash_resp.json()

        assert "snapshot" in dash
        assert "period" in dash

        # Snapshot
        assert dash["snapshot"]["active_threats"] == 2
        assert dash["snapshot"]["currently_blocked_ips"] == 1

        # Period must match 24h KPIs exactly
        assert dash["period"]["total_threats"] == kpis_24h["total_threats"]
        assert dash["period"]["critical_threats"] == kpis_24h["critical_threats"]
        assert dash["period"]["response_actions"] == kpis_24h["response_actions"]
        assert dash["period"]["recorded_blocks"] == kpis_24h["recorded_blocks"]

    # ── Reports endpoint verification ─────────────────────────────
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 24h
        rep_24h_resp = await client.get("/api/v1/reporting/dashboard?time_range=24h")
        assert rep_24h_resp.status_code == 200
        rep_24h = rep_24h_resp.json()
        rep_kpis_24h = rep_24h["kpis"]

        # Dashboard period == Reports 24h
        assert dash["period"]["total_threats"] == rep_kpis_24h["total_threats"], \
            "Dashboard period.total_threats must equal Reports 24h total_threats"
        assert dash["period"]["response_actions"] == rep_kpis_24h["response_actions"], \
            "Dashboard period.response_actions must equal Reports 24h response_actions"
        assert dash["period"]["recorded_blocks"] == rep_kpis_24h["recorded_blocks"], \
            "Dashboard period.recorded_blocks must equal Reports 24h recorded_blocks"

        # 7d
        rep_7d_resp = await client.get("/api/v1/reporting/dashboard?time_range=7d")
        assert rep_7d_resp.status_code == 200
        rep_kpis_7d = rep_7d_resp.json()["kpis"]

        # Reports 24h != Reports 7d
        assert rep_kpis_24h["total_threats"] != rep_kpis_7d["total_threats"], \
            "Reports 24h and 7d must return different totals when data spans boundaries"

        # Reports 7d matches direct AnalyticsService
        assert rep_kpis_7d["total_threats"] == kpis_7d["total_threats"]
        assert rep_kpis_7d["response_actions"] == kpis_7d["response_actions"]

    print("✓ Cross-endpoint consistency and time-range differentiation verified")


# ═══════════════════════════════════════════════════════════════════
# TEST 2: Blocked-IP reconstruction edge cases
# ═══════════════════════════════════════════════════════════════════
@pytest.mark.asyncio
async def test_rb009_blocked_ip_edge_cases():
    """Deterministic blocked-IP reconstruction under adversarial sequences."""
    await init_db()
    db = await get_db_client()
    now = _utc_now()

    await _clean_tables(db)

    analytics = AnalyticsService(db)

    # ── Case 1: BLOCK → BLOCK → UNBLOCK → BLOCK = blocked ────────
    for i, action in enumerate(["BLOCK", "BLOCK", "UNBLOCK", "BLOCK"]):
        await db.table("firewall_actions").insert({
            "ip": "10.0.0.1", "action": action,
            "created_at": (now - timedelta(minutes=40 - i * 10)).isoformat()
        }).execute()

    blocked = await analytics._count_currently_blocked_ips()
    assert blocked == 1, f"BLOCK→BLOCK→UNBLOCK→BLOCK should yield 1 blocked, got {blocked}"

    # ── Case 2: UNBLOCK without prior BLOCK = not blocked ─────────
    await db.table("firewall_actions").insert({
        "ip": "10.0.0.2", "action": "UNBLOCK",
        "created_at": (now - timedelta(minutes=5)).isoformat()
    }).execute()

    blocked = await analytics._count_currently_blocked_ips()
    assert blocked == 1, f"Orphan UNBLOCK must not create a blocked entry, got {blocked}"

    # ── Case 3: BLOCK A, BLOCK B, UNBLOCK A = 1 blocked (B only) ─
    empty_uuid = "00000000-0000-0000-0000-000000000000"
    await db.table("firewall_actions").delete().neq("id", empty_uuid).execute()

    await db.table("firewall_actions").insert({
        "ip": "10.0.0.A", "action": "BLOCK",
        "created_at": (now - timedelta(minutes=30)).isoformat()
    }).execute()
    await db.table("firewall_actions").insert({
        "ip": "10.0.0.B", "action": "BLOCK",
        "created_at": (now - timedelta(minutes=20)).isoformat()
    }).execute()
    await db.table("firewall_actions").insert({
        "ip": "10.0.0.A", "action": "UNBLOCK",
        "created_at": (now - timedelta(minutes=10)).isoformat()
    }).execute()

    blocked = await analytics._count_currently_blocked_ips()
    assert blocked == 1, f"BLOCK A + BLOCK B + UNBLOCK A should yield 1 blocked, got {blocked}"

    # ── Case 4: Empty table = 0 blocked ───────────────────────────
    await db.table("firewall_actions").delete().neq("id", empty_uuid).execute()

    blocked = await analytics._count_currently_blocked_ips()
    assert blocked == 0, f"Empty table should yield 0 blocked, got {blocked}"

    print("✓ Blocked-IP reconstruction edge cases verified")


# ═══════════════════════════════════════════════════════════════════
# TEST 3: Response actions do not double-count
# ═══════════════════════════════════════════════════════════════════
@pytest.mark.asyncio
async def test_rb009_no_double_counting():
    """Each action type contributes exactly once to response_actions."""
    await init_db()
    db = await get_db_client()
    now = _utc_now()

    await _clean_tables(db)

    # Insert exactly: 1 BLOCK, 1 UNBLOCK, 1 RESOLVE, 1 IGNORE
    await db.table("firewall_actions").insert({
        "ip": "10.0.0.1", "action": "BLOCK",
        "created_at": (now - timedelta(hours=1)).isoformat()
    }).execute()
    await db.table("firewall_actions").insert({
        "ip": "10.0.0.1", "action": "UNBLOCK",
        "created_at": (now - timedelta(minutes=30)).isoformat()
    }).execute()
    await db.table("audit_logs").insert({
        "action": "RESOLVE", "resource": "RESPONSE", "ip_address": "10.0.0.2",
        "created_at": (now - timedelta(minutes=20)).isoformat()
    }).execute()
    await db.table("audit_logs").insert({
        "action": "IGNORE", "resource": "RESPONSE", "ip_address": "10.0.0.3",
        "created_at": (now - timedelta(minutes=10)).isoformat()
    }).execute()

    analytics = AnalyticsService(db)
    kpis = await analytics.get_kpis("24h")

    assert kpis["response_actions"] == 4, \
        f"1 BLOCK + 1 UNBLOCK + 1 RESOLVE + 1 IGNORE = 4, got {kpis['response_actions']}"
    assert kpis["recorded_blocks"] == 1, \
        f"Only 1 BLOCK action, got {kpis['recorded_blocks']}"

    print("✓ No double-counting verified")
