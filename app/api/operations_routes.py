"""
CyberSentinel — Operations Query Routes
=========================================
Read-only endpoints for querying stored packets, firewall logs,
threat scores, and dashboard aggregation statistics.
"""

import logging
import random
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query, UploadFile, File, HTTPException, status, Header
from fastapi.responses import JSONResponse

from app.repositories import (
    get_packet_repo,
    get_firewall_repo,
    get_threat_score_repo,
    get_virus_repo,
    get_threat_alert_repo,
)
from app.api.auth_dependencies import require_admin
from app.repositories.repositories import (
    PacketRepository,
    FirewallLogRepository,
    ThreatScoreRepository,
    VirusScanRepository,
    ThreatAlertRepository,
)
from app.schemas.packet import PacketListResponse
from app.schemas.firewall import FirewallLogListResponse
from app.schemas.dashboard import (
    DashboardStatsResponse,
    PacketClassification,
    MaliciousIPEntry,
    DashboardSnapshot,
    DashboardPeriod,
)
from app.schemas.threat_alert import (
    ThreatAlertResponse,
    ThreatAlertListResponse,
    ThreatAlertStatsResponse,
    ThreatAlertStatusUpdate,
)
from app.schemas.firewall_import import FirewallImportResponse
from app.schemas.operations import VirusScanResponse, ScanStatus
from app.services.virus_scanner.scanner_service import VirusScannerService
from app.services.threat_response.alert_service import AlertService
from app.services.threat_response.alert_filters import AlertFilters
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Operations"])



# ── Packet History ────────────────────────────────────────────────────────────

@router.get("/packets", response_model=PacketListResponse)
async def list_packets(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    repo: PacketRepository = Depends(get_packet_repo),
):
    """Fetch paginated packet capture history from the database."""
    rows, total = await repo.list(
        order_by="captured_at", descending=True, page=page, page_size=page_size
    )
    return {"items": rows, "total": total, "page": page, "page_size": page_size}


# ── Firewall Log History ──────────────────────────────────────────────────────

@router.get("/operations/firewall", response_model=FirewallLogListResponse)
async def list_firewall_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    repo: FirewallLogRepository = Depends(get_firewall_repo),
):
    """Fetch paginated firewall log history from the database."""
    rows, total = await repo.list(
        order_by="logged_at", descending=True, page=page, page_size=page_size
    )
    return {"items": rows, "total": total, "page": page, "page_size": page_size}


# ── Helper for Backwards Compatibility ────────────────────────────────────────

def format_alert_response(alert: dict) -> dict:
    """Ensure backward compatibility with threat_score UI expectations."""
    # Wrap our summary in a single-item list as the reasoning field expected by older providers
    reasoning = [alert.get("summary", "No details available.")]

    return {
        "alert_id": alert.get("alert_id"),
        "id": alert.get("alert_id"),  # Alias for UUID lookups
        "source_ip": alert.get("source_ip"),
        "severity": alert.get("severity"),
        "action": alert.get("action"),
        "status": alert.get("status"),
        "threat_score": alert.get("threat_score"),
        "summary": alert.get("summary"),
        "explanation": alert.get("explanation") or [],
        "trace_id": alert.get("trace_id"),
        "model1_score": alert.get("model1_score"),
        "model2_score": alert.get("model2_score"),
        "model3_score": alert.get("model3_score"),
        "model1_classification": alert.get("model1_classification"),
        "model2_severity": alert.get("model2_severity"),
        "model3_severity": alert.get("model3_severity"),
        "occurrence_count": alert.get("occurrence_count", 1),
        "timeline": alert.get("timeline") or [],
        "context_ready": alert.get("context_ready", True),
        "created_at": alert.get("created_at"),
        "updated_at": alert.get("updated_at"),
        # Legacy aliases
        "scored_at": alert.get("created_at"),
        "reasoning": reasoning,
        "recommendation": alert.get("action")
    }


# ── Threat Alerts (Phase 7 SOC Threat Response Center) ───────────────────────

@router.get("/threats")
async def list_threats(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    repo: ThreatAlertRepository = Depends(get_threat_alert_repo),
):
    """Fetch paginated threat alerts."""
    rows, total = await repo.get_all(page=page, page_size=page_size)
    items = [format_alert_response(r) for r in rows]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/threats/open")
async def list_open_threats(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    repo: ThreatAlertRepository = Depends(get_threat_alert_repo),
):
    """Fetch alerts that are currently active (OPEN or INVESTIGATING)."""
    rows, total = await repo.get_history(status="OPEN", page=page, page_size=page_size)
    investigating_rows, investigating_total = await repo.get_history(status="INVESTIGATING", page=page, page_size=page_size)

    # Combine lists
    combined_rows = rows + investigating_rows
    # Sort combined rows by updated_at or created_at descending
    combined_rows.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    # Slice according to pagination
    offset = (page - 1) * page_size
    sliced = combined_rows[offset:offset + page_size]

    items = [format_alert_response(r) for r in sliced]
    return {
        "items": items,
        "total": total + investigating_total,
        "page": page,
        "page_size": page_size
    }


@router.get("/threats/history")
async def threat_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    repo: ThreatAlertRepository = Depends(get_threat_alert_repo),
):
    """Full paginated threat history with robust operational filters."""
    sanitized = AlertFilters.sanitize_history_params(
        severity=severity,
        status=status,
        ip=ip,
        start_date=start_date,
        end_date=end_date
    )

    rows, total = await repo.get_history(
        severity=sanitized["filters"].get("severity"),
        status=sanitized["filters"].get("status"),
        ip=sanitized["filters"].get("source_ip"),
        start_date=sanitized["start_date"],
        end_date=sanitized["end_date"],
        page=page,
        page_size=page_size
    )
    items = [format_alert_response(r) for r in rows]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/threats/high")
async def list_high_threats(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    repo: ThreatAlertRepository = Depends(get_threat_alert_repo),
):
    """Fetch high-severity alerts (HIGH and CRITICAL)."""
    rows, total = await repo.get_by_severity(["HIGH", "CRITICAL"], page=page, page_size=page_size)
    items = [format_alert_response(r) for r in rows]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/threats/critical")
async def list_critical_threats(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    repo: ThreatAlertRepository = Depends(get_threat_alert_repo),
):
    """Fetch critical-severity alerts (CRITICAL only)."""
    rows, total = await repo.get_by_severity(["CRITICAL"], page=page, page_size=page_size)
    items = [format_alert_response(r) for r in rows]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/threats/stats")
async def get_threat_stats(
    repo: ThreatAlertRepository = Depends(get_threat_alert_repo),
):
    """Get active, severity, and status counts for threat alerts."""
    return await repo.get_stats()


@router.get("/threats/{alert_id}")
async def get_investigation_record(
    alert_id: str,
    repo: ThreatAlertRepository = Depends(get_threat_alert_repo),
):
    """Fetch a single comprehensive alert record for SOC investigation."""
    alert = await repo.get_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat alert with ID {alert_id} not found."
        )
    return format_alert_response(alert)


@router.patch("/threats/{alert_id}/status")
async def update_lifecycle_status(
    alert_id: str,
    payload: ThreatAlertStatusUpdate,
    repo: ThreatAlertRepository = Depends(get_threat_alert_repo),
):
    """Update lifecycle status of a threat alert and log transition to timeline."""
    service = AlertService(repo)
    try:
        updated = await service.update_status(
            alert_id=alert_id,
            new_status=payload.status,
            notes=payload.notes
        )
        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Threat alert with ID {alert_id} not found."
            )
        return format_alert_response(updated)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )


# ── Dashboard Statistics ──────────────────────────────────────────────────────

@router.get("/dashboard/stats", response_model=DashboardStatsResponse)
async def get_dashboard_stats(
    packet_repo: PacketRepository = Depends(get_packet_repo),
    firewall_repo: FirewallLogRepository = Depends(get_firewall_repo),
    alert_repo: ThreatAlertRepository = Depends(get_threat_alert_repo),
):
    """Aggregated dashboard KPIs: threat score, counts, classification, top IPs."""
    from app.services.threat_response.stats_service import get_full_dashboard_stats
    stats_dict = await get_full_dashboard_stats(packet_repo=packet_repo, alert_repo=alert_repo)

    # Map the dictionary back into the Pydantic models for the response
    malicious_ips = [
        MaliciousIPEntry(**ip)
        for ip in stats_dict.get("malicious_ips", [])
    ]

    return DashboardStatsResponse(
        threat_score=stats_dict["threat_score"],
        snapshot=DashboardSnapshot(**stats_dict["snapshot"]),
        period=DashboardPeriod(**stats_dict["period"]),
        total_packets_count=stats_dict["total_packets_count"],
        suspicious_ips_count=stats_dict["suspicious_ips_count"],
        packet_classification=PacketClassification(**stats_dict["packet_classification"]),
        malicious_ips=malicious_ips,
    )


@router.post("/operations/firewall/upload", response_model=FirewallImportResponse)
async def upload_firewall_log(
    file: UploadFile = File(...),
    repo: FirewallLogRepository = Depends(get_firewall_repo),
    analyst=Depends(require_admin), # Only admins can upload firewall logs
):
    """Parses, validates, and atomically imports a firewall log file."""
    import hashlib
    import json

    from app.services.firewall_log_parser import parse_firewall_log, FirewallLogFormat
    from app.schemas.firewall_import import FirewallImportErrorResponse

    # 1. 5MB File Bounds Check
    MAX_FILE_SIZE = 5 * 1024 * 1024
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=FirewallImportErrorResponse(
                status="file_too_large",
                message="File exceeds the 5MB upload limit."
            ).model_dump()
        )
    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=FirewallImportErrorResponse(
                status="empty_file",
                message="Uploaded file is empty."
            ).model_dump()
        )

    # Decode content
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=FirewallImportErrorResponse(
                status="unsupported_encoding",
                message="File must be UTF-8 encoded text."
            ).model_dump()
        )

    # Calculate SHA256
    file_sha256 = hashlib.sha256(content).hexdigest()

    # Parse log
    parse_result = parse_firewall_log(text)

    if parse_result.format == FirewallLogFormat.empty:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=FirewallImportErrorResponse(
                status="empty_file",
                message="File contains no parseable lines."
            ).model_dump()
        )

    if parse_result.format == FirewallLogFormat.unsupported:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=FirewallImportErrorResponse(
                status="unsupported_format",
                message="Unsupported log format. Only UFW and Windows Defender logs are supported."
            ).model_dump()
        )

    if not parse_result.imported:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=FirewallImportErrorResponse(
                status="no_parseable_entries",
                message="File was parsed but yielded no valid firewall entries."
            ).model_dump()
        )

    # Perform Database RPC call for Atomic Import
    try:
        # result is a JSON string from Postgres, or None
        # It's an internal error if it doesn't return the import ID
        import_id = await repo.import_firewall_batch_atomic(
            file_sha256=file_sha256,
            source_filename=file.filename,
            source_format=parse_result.format.value,
            imported_count=len(parse_result.imported),
            rejected_count=len(parse_result.rejected),
            imported_by=str(analyst.user_id),
            entries=parse_result.imported
        )
    except Exception as exc:
        err_str = str(exc)
        if "duplicate_import" in err_str or "duplicate key value violates unique constraint" in err_str:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=FirewallImportErrorResponse(
                    status="duplicate_import",
                    message="This file has already been imported."
                ).model_dump()
            )
        logger.exception("Database error during atomic firewall import: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=FirewallImportErrorResponse(
                status="unavailable",
                message="A database error occurred during import."
            ).model_dump()
        )

    return FirewallImportResponse(
        format=parse_result.format.value,
        imported=len(parse_result.imported),
        rejected=len(parse_result.rejected),
        rejected_details=parse_result.rejected,
        warnings=parse_result.warnings
    )


@router.post("/virus/scan", response_model=VirusScanResponse)
async def scan_virus(
    target: str = Query(..., description="URL, Hash, or IP"),
    scan_type: str = Query(..., alias="type"),
    authorization: Optional[str] = Header(default=None),
    repo: VirusScanRepository = Depends(get_virus_repo)
) -> JSONResponse:
    auth_token = None
    if authorization and authorization.startswith("Bearer "):
        auth_token = authorization.split(" ")[1]

    service = VirusScannerService(repository=repo)
    result = await service.scan(target, scan_type, auth_token=auth_token)

    if result.status == ScanStatus.invalid_target:
        raise HTTPException(status_code=400, detail=result.message)
    elif result.status == ScanStatus.not_found:
        raise HTTPException(status_code=404, detail=result.message)
    elif result.status == ScanStatus.quota_exceeded:
        raise HTTPException(status_code=429, detail=result.message)
    elif result.status == ScanStatus.unavailable:
        raise HTTPException(status_code=503, detail=result.message)

    from fastapi.responses import JSONResponse
    status_code = 202 if result.status == ScanStatus.pending else 200
    return JSONResponse(status_code=status_code, content=result.model_dump(mode="json"))

@router.post("/virus/scan-file", response_model=VirusScanResponse)
async def scan_virus_file(
    file: UploadFile = File(...),
    authorization: Optional[str] = Header(default=None),
    repo: VirusScanRepository = Depends(get_virus_repo)
) -> JSONResponse:
    import hashlib
    from fastapi.responses import JSONResponse

    auth_token = None
    if authorization and authorization.startswith("Bearer "):
        auth_token = authorization.split(" ")[1]

    h = hashlib.sha256()
    size = 0
    limit = 10 * 1024 * 1024  # 10MB
    while chunk := await file.read(8192):
        size += len(chunk)
        if size > limit:
            return JSONResponse(
                status_code=400,
                content={
                    "target": file.filename,
                    "scan_type": "file",
                    "status": "file_too_large",
                    "message": "File size exceeds the 10MB limit.",
                    "provider": "VIRUSTOTAL",
                    "provider_contacted": False
                }
            )
        h.update(chunk)
    file_hash = h.hexdigest()

    service = VirusScannerService(repository=repo)
    result = await service.scan(file_hash, "hash", auth_token=auth_token)

    if result.status == ScanStatus.invalid_target:
        raise HTTPException(status_code=400, detail=result.message)
    elif result.status == ScanStatus.not_found:
        raise HTTPException(status_code=404, detail=result.message)
    elif result.status == ScanStatus.quota_exceeded:
        raise HTTPException(status_code=429, detail=result.message)
    elif result.status == ScanStatus.unavailable:
        raise HTTPException(status_code=503, detail=result.message)

    status_code = 202 if result.status == ScanStatus.pending else 200
    return JSONResponse(status_code=status_code, content=result.model_dump(mode="json"))
