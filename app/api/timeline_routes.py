import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.repositories import (
    get_threat_alert_repo,
    get_firewall_action_repo,
    get_analyst_note_repo,
)
from app.repositories.repositories import (
    ThreatAlertRepository,
    FirewallActionRepository,
    AnalystNoteRepository,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/alerts", tags=["Investigation Timeline"])


class TimelineEvent(BaseModel):
    timestamp: str
    event: str
    details: Optional[Dict[str, Any]] = None


@router.get("/{alert_id}/timeline", response_model=List[TimelineEvent])
async def get_alert_timeline(
    alert_id: str,
    alert_repo: ThreatAlertRepository = Depends(get_threat_alert_repo),
    firewall_repo: FirewallActionRepository = Depends(get_firewall_action_repo),
    note_repo: AnalystNoteRepository = Depends(get_analyst_note_repo),
):
    """
    Constructs a comprehensive SOC-style chronological timeline of an alert's lifecycle.
    """
    alert = await alert_repo.get_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat alert with ID {alert_id} not found."
        )

    timeline_events = []
    
    # 1. Base Event: Alert Created
    created_at_dt = alert.get("created_at") or datetime.now(timezone.utc).isoformat()
    timeline_events.append({
        "timestamp": created_at_dt,
        "event": "Alert Created",
        "details": {"severity": alert.get("severity")}
    })

    # 2. Decision Engine Detection Phases (simulated timings based on created_at)
    # We add 1 millisecond increments for realistic sequential display
    # Random Forest Detection
    if alert.get("model1_score") is not None:
        timeline_events.append({
            "timestamp": created_at_dt.replace("Z", ".001Z") if "Z" in created_at_dt else created_at_dt + "1",
            "event": "Random Forest Detection",
            "details": {"score": alert.get("model1_score"), "classification": alert.get("model1_classification")}
        })
    
    # Isolation Forest Detection
    if alert.get("model2_score") is not None:
        timeline_events.append({
            "timestamp": created_at_dt.replace("Z", ".002Z") if "Z" in created_at_dt else created_at_dt + "2",
            "event": "Isolation Forest Detection",
            "details": {"anomaly_score": alert.get("model2_score"), "severity": alert.get("model2_severity")}
        })
        
    # Threat Intelligence Analysis
    if alert.get("model3_score") is not None:
        timeline_events.append({
            "timestamp": created_at_dt.replace("Z", ".003Z") if "Z" in created_at_dt else created_at_dt + "3",
            "event": "Threat Intelligence Check",
            "details": {"reputation_score": alert.get("model3_score")}
        })
        
    # Final Score Generated
    timeline_events.append({
        "timestamp": created_at_dt.replace("Z", ".004Z") if "Z" in created_at_dt else created_at_dt + "4",
        "event": "Threat Score Generated",
        "details": {"final_score": alert.get("threat_score")}
    })
    
    # 3. AI Explanation
    if alert.get("explanation"):
        # If there's an explanation, it typically generates shortly after alert creation
        timeline_events.append({
            "timestamp": created_at_dt.replace("Z", ".005Z") if "Z" in created_at_dt else created_at_dt + "5",
            "event": "AI Explanation Generated",
            "details": {"models_analyzed": len(alert.get("explanation"))}
        })

    # 4. Embedded Alert Timeline (Status Changes / Occurrence Increments)
    embedded_timeline = alert.get("timeline") or []
    for ev in embedded_timeline:
        event_name = ev.get("event", "UNKNOWN")
        if event_name == "STATUS_CHANGED":
            timeline_events.append({
                "timestamp": ev.get("timestamp"),
                "event": f"Status changed to {ev.get('status')}",
                "details": {"notes": ev.get("notes")}
            })
        elif event_name == "DUPLICATE_OCCURRENCE":
            timeline_events.append({
                "timestamp": ev.get("timestamp"),
                "event": "Duplicate Occurrence Detected",
                "details": {"occurrence_number": ev.get("occurrence_number")}
            })
        else:
            timeline_events.append({
                "timestamp": ev.get("timestamp", created_at_dt),
                "event": event_name,
                "details": ev
            })

    # 5. Analyst Notes
    try:
        notes = await note_repo.get_by_alert(alert_id)
        for note in notes:
            timeline_events.append({
                "timestamp": note.get("created_at"),
                "event": "Analyst Added Note",
                "details": {"author": note.get("author"), "note": note.get("note")}
            })
    except Exception as e:
        logger.warning(f"Failed to fetch analyst notes (table might not exist): {e}")

    # 6. Firewall Actions (Filter by IP and timestamp >= alert created_at)
    source_ip = alert.get("source_ip")
    if source_ip:
        fw_actions = await firewall_repo.get_actions_for_ip(source_ip)
        for act in fw_actions:
            act_time = act.get("created_at")
            # Only include firewall actions that happened AFTER the alert was created
            if act_time and act_time >= created_at_dt:
                timeline_events.append({
                    "timestamp": act_time,
                    "event": f"Firewall Rule Applied ({act.get('action')})",
                    "details": {"ip": source_ip, "reason": act.get("reason"), "rule_name": act.get("rule_name")}
                })

    # Sort the unified timeline chronologically
    timeline_events.sort(key=lambda x: x["timestamp"])

    return [TimelineEvent(**ev) for ev in timeline_events]
