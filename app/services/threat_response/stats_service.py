from app.repositories.repositories import ThreatAlertRepository, PacketRepository
from app.database.client import get_db_client
import logging

logger = logging.getLogger(__name__)


async def _safe_stat(label: str, operation, default):
    """Keep optional dashboard metrics from failing the whole snapshot."""
    try:
        return await operation()
    except Exception as exc:
        logger.warning("Dashboard metric %s unavailable: %s", label, type(exc).__name__)
        return default

class StatsService:
    def __init__(self, repo: ThreatAlertRepository) -> None:
        self.repo = repo

    async def get_threat_stats(self) -> dict:
        """Fetch unified counts and status metrics for all threat alerts."""
        return await self.repo.get_stats()

async def get_full_dashboard_stats(
    packet_repo: PacketRepository = None,
    alert_repo: ThreatAlertRepository = None,
    analytics = None
) -> dict:
    """Fetch and compute all metrics needed for the main SOC dashboard."""
    if packet_repo is None or alert_repo is None or analytics is None:
        db = (
            getattr(packet_repo, "_db", None)
            or getattr(alert_repo, "_db", None)
            or await get_db_client()
        )
        if packet_repo is None:
            packet_repo = PacketRepository(db)
        if alert_repo is None:
            alert_repo = ThreatAlertRepository(db)
        if analytics is None:
            from app.services.reporting.analytics_service import AnalyticsService
            analytics = AnalyticsService(db)

    # Packet classification counts
    packet_stats = await _safe_stat("packet_classification", packet_repo.get_stats, {})
    total_packets = sum(packet_stats.values())
    
    # Snapshot metrics
    active_threats = await _safe_stat(
        "active_threats", analytics._count_active_threats, 0
    )
    currently_blocked_ips = await _safe_stat(
        "currently_blocked_ips", analytics._count_currently_blocked_ips, 0
    )

    # Period metrics
    kpis_24h = await _safe_stat(
        "period_kpis", lambda: analytics.get_kpis("24h"), {}
    )

    # Calculate average threat score based on all logged alerts
    rows, _ = await _safe_stat(
        "recent_alerts", lambda: alert_repo.get_all(page_size=200), ([], 0)
    )
    scores = [r.get("threat_score", 0) for r in rows if r.get("threat_score") is not None]
    avg_score = int(sum(scores) / len(scores)) if scores else 0

    # Top malicious IPs
    ip_counts = {}
    for r in rows:
        if r.get("threat_score", 0) > 50:
            ip = r.get("source_ip", "unknown")
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    malicious_ips = [
        {
            "ip": ip, 
            "country": "External", 
            "requests": count, 
            "threat_level": "High"
        }
        for ip, count in top_ips
    ]

    # Get capture diagnostics
    from app.services.packet_capture.capture_service import get_capture_service
    try:
        capture_svc = get_capture_service()
        capture_status = capture_svc.get_status()
    except Exception:
        capture_status = {"state": "unknown", "error": "Capture service not initialized"}

    return {
        "threat_score": avg_score,
        "snapshot": {
            "active_threats": active_threats,
            "currently_blocked_ips": currently_blocked_ips,
            "capture_diagnostics": capture_status,
        },
        "period": {
            "time_range": "24h",
            "total_threats": kpis_24h.get("total_threats", 0),
            "critical_threats": kpis_24h.get("critical_threats", 0),
            "response_actions": kpis_24h.get("response_actions", 0),
            "recorded_blocks": kpis_24h.get("recorded_blocks", 0),
        },
        "total_packets_count": total_packets,
        "suspicious_ips_count": len(ip_counts),
        "packet_classification": {
            "normal": packet_stats.get("Normal", 0),
            "suspicious": packet_stats.get("Suspicious", 0),
            "malicious": packet_stats.get("Malicious", 0),
        },
        "malicious_ips": malicious_ips,
    }
