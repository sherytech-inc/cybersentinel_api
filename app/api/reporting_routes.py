from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from supabase import AsyncClient
import json

from app.database.client import get_db_client
from app.services.reporting.report_service import ReportService

router = APIRouter(prefix="/api/v1/reporting", tags=["Reporting & Intelligence Center — Phase 9"])

def get_report_service(db: AsyncClient = Depends(get_db_client)) -> ReportService:
    return ReportService(db)

@router.get("/dashboard")
async def get_dashboard(
    time_range: str = Query("24h", description="Time range (24h, 7d, 30d)"),
    service: ReportService = Depends(get_report_service)
):
    """Returns all data required for the Reporting Dashboard."""
    return await service.get_dashboard_data(time_range)

@router.post("/snapshots")
async def create_snapshot(
    time_range: str = Query("24h"),
    service: ReportService = Depends(get_report_service)
):
    """Generates and saves a report snapshot."""
    snapshot = await service.create_snapshot(time_range)
    if not snapshot:
        raise HTTPException(status_code=500, detail="Failed to create snapshot")
    return snapshot

@router.get("/snapshots")
async def list_snapshots(service: ReportService = Depends(get_report_service)):
    """Lists saved report snapshots."""
    return await service.get_snapshots()

@router.get("/export/pdf")
async def export_pdf(
    time_range: str = Query("24h"),
    service: ReportService = Depends(get_report_service)
):
    """Downloads the Executive Security Report as PDF."""
    pdf_bytes = await service.export.generate_pdf_report(time_range)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=CyberSentinel_Report_{time_range}.pdf"}
    )

@router.get("/export/csv")
async def export_csv(
    type: str = Query("alerts", description="alerts or actions"),
    time_range: str = Query("24h"),
    service: ReportService = Depends(get_report_service)
):
    """Downloads threat alerts or firewall actions as CSV."""
    csv_str = await service.export.generate_csv(type, time_range)
    return Response(
        content=csv_str,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=CyberSentinel_{type}_{time_range}.csv"}
    )

@router.get("/export/json")
async def export_json(
    time_range: str = Query("24h"),
    service: ReportService = Depends(get_report_service)
):
    """Downloads full intelligence export as JSON."""
    data = await service.export.generate_json(time_range)
    return Response(
        content=json.dumps(data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=CyberSentinel_Intelligence_{time_range}.json"}
    )
