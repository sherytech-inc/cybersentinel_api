from pathlib import Path

from fastapi import APIRouter, Depends, File, UploadFile

from app.api.auth_dependencies import AnalystIdentity, get_current_analyst
from app.core.config import get_settings
from app.schemas.operations import (
    HashScanRequest,
    ScanStatus,
    URLScanRequest,
    VirusScanResponse,
)
from app.services.virus_scanner.scanner_service import VirusScannerService

router = APIRouter(prefix="/api/v1/scanner", tags=["Virus Scanner"])


@router.post("/url", response_model=VirusScanResponse)
async def scan_url(
    body: URLScanRequest,
    analyst: AnalystIdentity = Depends(get_current_analyst),
):
    return await VirusScannerService().scan_url(body.url)


@router.post("/hash", response_model=VirusScanResponse)
async def scan_hash(
    body: HashScanRequest,
    analyst: AnalystIdentity = Depends(get_current_analyst),
):
    return await VirusScannerService().scan_hash(body.hash)


@router.post("/file", response_model=VirusScanResponse)
async def scan_file(
    file: UploadFile = File(...),
    analyst: AnalystIdentity = Depends(get_current_analyst),
):
    limit = get_settings().VIRUS_SCANNER_MAX_FILE_BYTES
    chunks = []
    size = 0
    while chunk := await file.read(64 * 1024):
        size += len(chunk)
        if size > limit:
            return VirusScanResponse(
                target=Path(file.filename or "selected-file").name,
                scan_type="file",
                status=ScanStatus.file_too_large,
                verdict="unknown",
                message="File size exceeds the 10 MB limit.",
            )
        chunks.append(chunk)
    content = b"".join(chunks)
    return await VirusScannerService().scan_file(Path(file.filename or "selected-file").name, content)
