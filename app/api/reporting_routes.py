"""Authenticated local reporting and export routes."""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from supabase import AsyncClient

from app.api.auth_dependencies import get_current_analyst
from app.database.client import get_db_client
from app.schemas.reporting import ReportSummary
from app.services.reporting.report_service import ReportService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/reporting",
    tags=["Reporting & Intelligence Center — Phase 9"],
    dependencies=[Depends(get_current_analyst)],
)


def get_report_service(
    db: AsyncClient = Depends(get_db_client),
) -> ReportService:
    return ReportService(db)


def _filename_timestamp(summary: ReportSummary) -> str:
    return summary.generated_at.strftime("%Y%m%d-%H%M%S")


def _safe_unavailable(exc: Exception) -> HTTPException:
    logger.warning("Report request unavailable | type=%s", type(exc).__name__)
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="report_data_unavailable",
    )


@router.get("/summary", response_model=ReportSummary)
async def get_summary(
    service: ReportService = Depends(get_report_service),
):
    try:
        return await service.get_summary()
    except HTTPException:
        raise
    except Exception as exc:
        raise _safe_unavailable(exc) from exc


@router.post("/snapshots")
async def create_snapshot(
    time_range: str = Query("24h"),
    service: ReportService = Depends(get_report_service),
):
    snapshot = await service.create_snapshot(time_range)
    if not snapshot:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="report_snapshot_unavailable",
        )
    return snapshot


@router.get("/snapshots")
async def list_snapshots(
    service: ReportService = Depends(get_report_service),
):
    return await service.get_snapshots()


@router.get("/export/pdf")
async def export_pdf(
    service: ReportService = Depends(get_report_service),
):
    try:
        summary = await service.get_summary()
        pdf_bytes = service.export.generate_pdf_report(summary)
        filename = (
            f"cybersentinel-report-{_filename_timestamp(summary)}.pdf"
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            },
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise _safe_unavailable(exc) from exc


@router.get("/export/json")
async def export_json(
    service: ReportService = Depends(get_report_service),
):
    try:
        summary = await service.get_summary()
        filename = (
            f"cybersentinel-report-{_filename_timestamp(summary)}.json"
        )
        return Response(
            content=service.export.generate_json(summary),
            media_type="application/json; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            },
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise _safe_unavailable(exc) from exc


@router.get("/export/alerts.csv")
async def export_alerts_csv(
    service: ReportService = Depends(get_report_service),
):
    try:
        content, available = await service.export.generate_alerts_csv()
        if not available:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="report_alert_data_unavailable",
            )
        filename = (
            "cybersentinel-alerts-"
            f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.csv"
        )
        return Response(
            content=content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            },
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise _safe_unavailable(exc) from exc


@router.get("/export/actions.csv")
async def export_actions_csv(
    service: ReportService = Depends(get_report_service),
):
    try:
        content, available = await service.export.generate_actions_csv()
        if not available:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="report_action_data_unavailable",
            )
        filename = (
            "cybersentinel-actions-"
            f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.csv"
        )
        return Response(
            content=content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            },
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise _safe_unavailable(exc) from exc
