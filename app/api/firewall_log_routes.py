"""Authenticated, read-only firewall log analysis."""

import logging

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from app.api.auth_dependencies import AnalystIdentity, get_current_analyst
from app.schemas.firewall_analysis import (
    FirewallAnalysisError,
    FirewallAnalysisLimits,
    FirewallAnalysisResponse,
    FirewallAnalysisSummary,
)
from app.services.firewall_log_analysis import (
    MAX_EVENTS_RETURNED,
    MAX_LINE_LENGTH,
    MAX_LINES,
    MAX_UPLOAD_BYTES,
    MAX_WARNING_SAMPLES,
    FirewallFormat,
    count_ports,
    count_values,
    parse_firewall_text,
)

router = APIRouter(prefix="/api/v1/firewall-logs", tags=["Firewall Log Analysis"])
logger = logging.getLogger(__name__)


def _error(code: int, error_status: str, message: str) -> HTTPException:
    payload = FirewallAnalysisError(status=error_status, message=message)
    return HTTPException(status_code=code, detail=payload.model_dump())


@router.post("/analyze", response_model=FirewallAnalysisResponse)
async def analyze_firewall_log(
    file: UploadFile = File(...),
    _analyst: AnalystIdentity = Depends(get_current_analyst),
):
    """Analyze a supported firewall log entirely in memory."""
    try:
        content = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(content) > MAX_UPLOAD_BYTES:
            raise _error(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                "file_too_large",
                "File exceeds the 5 MB upload limit.",
            )
        if not content:
            raise _error(status.HTTP_400_BAD_REQUEST, "invalid_file", "Uploaded file is empty.")
        if b"\x00" in content:
            raise _error(status.HTTP_400_BAD_REQUEST, "invalid_file", "Binary files are not supported.")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            raise _error(
                status.HTTP_400_BAD_REQUEST,
                "invalid_file",
                "File must be UTF-8 encoded text.",
            )

        try:
            result = parse_firewall_text(text)
        except Exception as exc:
            logger.warning(
                "Firewall log parser unavailable: reason=%s",
                type(exc).__name__,
            )
            raise _error(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "unavailable",
                "Firewall Log Analysis is temporarily unavailable.",
            )

        safe_filename = (file.filename or "firewall-log.txt").replace("\\", "/").split("/")[-1][:255]
        suffix = safe_filename.rsplit(".", 1)[-1].lower() if "." in safe_filename else ""
        if suffix not in {"log", "txt", "csv"}:
            result.warnings.append(
                "The filename extension was unusual; the detected content format was used."
            )
        if file.content_type and not (
            file.content_type.startswith("text/")
            or file.content_type in {"application/csv", "application/octet-stream"}
        ):
            result.warnings.append(
                "The upload MIME type was unusual; the detected content format was used."
            )
        result.warnings = result.warnings[:MAX_WARNING_SAMPLES]
        if result.detected_format == FirewallFormat.unsupported:
            raise _error(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "unsupported_format",
                "Unsupported or unrecognized firewall log format.",
            )

        complete = sum(event.parse_status == "complete" for event in result.events)
        partial = sum(event.parse_status == "partial" for event in result.events)
        parsed = complete + partial
        if parsed == 0:
            raise _error(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "invalid_file",
                "No supported firewall events could be parsed.",
            )
        timestamps = sorted(event.timestamp for event in result.events if event.timestamp)
        summary = FirewallAnalysisSummary(
            detected_format=result.detected_format.value,
            total_lines=result.total_lines,
            parsed_events=parsed,
            complete_events=complete,
            partial_events=partial,
            failed_lines=result.failed_lines,
            allowed_count=sum(event.action == "allow" for event in result.events),
            denied_dropped_count=sum(event.action in {"deny", "drop", "reject"} for event in result.events),
            inbound_count=sum(event.direction == "inbound" for event in result.events),
            outbound_count=sum(event.direction == "outbound" for event in result.events),
            protocol_distribution=count_values([event.protocol for event in result.events]),
            top_source_ips=count_values([event.source_ip for event in result.events]),
            top_destination_ips=count_values([event.destination_ip for event in result.events]),
            top_destination_ports=count_ports([event.destination_port for event in result.events]),
            first_timestamp=timestamps[0] if timestamps else None,
            last_timestamp=timestamps[-1] if timestamps else None,
            malformed_line_count=result.failed_lines,
            warnings=result.warnings,
        )
        return FirewallAnalysisResponse(
            status="partial" if partial or result.failed_lines else "complete",
            filename=safe_filename,
            summary=summary,
            events=result.events[:MAX_EVENTS_RETURNED],
            events_truncated=result.events_truncated,
            limits=FirewallAnalysisLimits(
                max_upload_bytes=MAX_UPLOAD_BYTES,
                max_lines=MAX_LINES,
                max_line_length=MAX_LINE_LENGTH,
                max_events_returned=MAX_EVENTS_RETURNED,
                max_warning_samples=MAX_WARNING_SAMPLES,
            ),
        )
    finally:
        await file.close()
