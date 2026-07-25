"""
CyberSentinel — Firewall Action Routes
========================================
Endpoints for blocking, unblocking, and whitelisting IPs.
Currently stubs that log to the firewall_actions database table.
Backend firewall enforcement logic will be added in a future phase.
"""

import logging
from uuid import uuid4
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query

from app.repositories import get_firewall_action_repo
from app.repositories.repositories import FirewallActionRepository
from app.schemas.firewall_action import (
    FirewallActionRequest,
    FirewallActionResponse,
    FirewallActionListResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/firewall-action", tags=["Firewall Actions"])


async def _perform_action(
    action: str,
    request: FirewallActionRequest,
    repo: FirewallActionRepository,
    source: str = "USER",
) -> FirewallActionResponse:
    """Shared helper: log the firewall action to the database."""
    record = {
        "ip": request.ip,
        "action": action,
        "reason": request.reason,
        "source": source,
    }
    row = await repo.insert(record)
    if row:
        return FirewallActionResponse(
            id=row["id"],
            ip=row["ip"],
            action=row["action"],
            reason=row.get("reason"),
            source=row.get("source", source),
            created_at=row.get("created_at", datetime.now(timezone.utc)),
        )
    # Fallback if DB insert fails — still return a valid response
    return FirewallActionResponse(
        id=uuid4(),
        ip=request.ip,
        action=action,
        reason=request.reason,
        source=source,
        created_at=datetime.now(timezone.utc),
    )


@router.post("/block", response_model=FirewallActionResponse)
async def block_ip(
    request: FirewallActionRequest,
    repo: FirewallActionRepository = Depends(get_firewall_action_repo),
):
    """Block an IP address. Logs the action for audit and future enforcement."""
    logger.info("FIREWALL BLOCK requested for IP=%s reason=%s", request.ip, request.reason)
    return await _perform_action("BLOCK", request, repo)


@router.post("/unblock", response_model=FirewallActionResponse)
async def unblock_ip(
    request: FirewallActionRequest,
    repo: FirewallActionRepository = Depends(get_firewall_action_repo),
):
    """Unblock a previously blocked IP address."""
    logger.info("FIREWALL UNBLOCK requested for IP=%s", request.ip)
    return await _perform_action("UNBLOCK", request, repo)


@router.post("/whitelist", response_model=FirewallActionResponse)
async def whitelist_ip(
    request: FirewallActionRequest,
    repo: FirewallActionRepository = Depends(get_firewall_action_repo),
):
    """Whitelist an IP address — permanently exempt from blocking."""
    logger.info("FIREWALL WHITELIST requested for IP=%s", request.ip)
    return await _perform_action("WHITELIST", request, repo)


@router.get("/actions", response_model=FirewallActionListResponse)
async def list_firewall_actions(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    repo: FirewallActionRepository = Depends(get_firewall_action_repo),
):
    """List recent firewall actions."""
    rows, total = await repo.list(
        order_by="created_at", descending=True, page=page, page_size=page_size
    )
    return {"items": rows, "total": total, "page": page, "page_size": page_size}
