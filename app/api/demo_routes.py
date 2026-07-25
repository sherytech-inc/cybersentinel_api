"""
CyberSentinel — Demo Routing (Phase 11)
=======================================
Injects mock data (packets, firewall actions, alerts) to simulate network traffic 
and dashboard activity.
"""

import uuid
import random
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from app.repositories import (
    get_packet_repo,
    get_firewall_action_repo,
    get_threat_alert_repo,
    PacketRepository,
    FirewallActionRepository,
    ThreatAlertRepository,
)
from app.core.config import get_settings

router = APIRouter(prefix="/api/v1/demo", tags=["Demo Mode"])

def check_demo_mode():
    settings = get_settings()
    if not settings.ENABLE_DEMO_MODE:
        raise HTTPException(status_code=403, detail="Demo Mode is disabled in this environment.")

@router.get("/status")
async def get_demo_status(
    packet_repo: PacketRepository = Depends(get_packet_repo)
):
    settings = get_settings()
    if not settings.ENABLE_DEMO_MODE:
        return {"enabled": False, "active_runs": 0, "active_run_id": None, "active_scenario": None}
        
    from app.database.client import db_has_demo_columns
    if not db_has_demo_columns():
        from app.repositories.base import _in_memory_demo_store
        data = _in_memory_demo_store.get("packets", [])
        # Sort by captured_at descending
        data = sorted(data, key=lambda x: x.get("captured_at", ""), reverse=True)
        count = len(data)
    else:
        # Check if there are any demo packets
        res = await packet_repo._db.table(packet_repo._table).select("id, demo_run_id, demo_scenario").eq("is_demo", True).order("captured_at", desc=True).limit(1).execute()
        data = res.data if res and hasattr(res, 'data') else []
        
        count_res = await packet_repo._db.table(packet_repo._table).select("id", count="exact").eq("is_demo", True).limit(1).execute()
        count = count_res.count if count_res and hasattr(count_res, 'count') and count_res.count is not None else 0
        
    active_run_id = data[0].get("demo_run_id") if data else None
    active_scenario = data[0].get("demo_scenario") if data else None

    return {
        "enabled": True, 
        "active_runs": 1 if count > 0 else 0,
        "active_run_id": active_run_id,
        "active_scenario": active_scenario
    }


@router.post("/load")
async def load_demo_scenario(
    scenario: str = Query(..., description="Scenario name: port_scan, ddos, brute_force, mixed"),
    packet_repo: PacketRepository = Depends(get_packet_repo),
    firewall_repo: FirewallActionRepository = Depends(get_firewall_action_repo),
    alert_repo: ThreatAlertRepository = Depends(get_threat_alert_repo)
):
    check_demo_mode()
    
    valid_scenarios = ["port_scan", "ddos", "brute_force", "mixed"]
    if scenario not in valid_scenarios:
        raise HTTPException(status_code=400, detail=f"Invalid scenario. Choose from {valid_scenarios}")

    demo_run_id = str(uuid.uuid4())
    num_packets = random.randint(50, 100)
    session_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    
    attacker_ip = f"192.168.1.{random.randint(100, 200)}"
    target_ip = "10.0.0.5"
    
    # 1. Inject Packets
    packets_to_insert = []
    for i in range(num_packets):
        packet_time = now - timedelta(seconds=(num_packets - i) * 0.5)
        
        if scenario == "ddos":
            p_size = random.randint(1000, 1500)
            sev = "HIGH"
        elif scenario == "port_scan":
            p_size = random.randint(40, 100)
            sev = "Suspicious" if i % 2 == 0 else "Normal"
        elif scenario == "brute_force":
            p_size = random.randint(200, 400)
            sev = "HIGH" if i % 5 == 0 else "Suspicious"
        else: # mixed
            p_size = random.randint(40, 1500)
            sev = random.choice(["Normal", "Suspicious", "HIGH", "CRITICAL"])
            
        packets_to_insert.append({
            "session_id": session_id,
            "source_ip": attacker_ip if sev != "Normal" else f"192.168.1.{random.randint(10, 50)}",
            "destination_ip": target_ip,
            "source_port": random.randint(1024, 65535),
            "destination_port": random.choice([22, 80, 443, 3306]),
            "protocol": "TCP",
            "packet_size": p_size,
            "severity": sev,
            "captured_at": packet_time.isoformat(),
            "is_demo": True,
            "demo_scenario": scenario,
            "demo_run_id": demo_run_id
        })
        
    await packet_repo.insert_many(packets_to_insert)
        
    alert_id = str(uuid.uuid4())
    
    scenario_label = {
        "port_scan": "Port Scan",
        "ddos": "DDoS",
        "brute_force": "Brute Force",
        "mixed": "Mixed Attack"
    }.get(scenario, "Suspicious Traffic")

    await alert_repo.insert({
        "alert_id": alert_id,
        "source_ip": attacker_ip,
        "severity": "CRITICAL" if scenario in ["ddos", "mixed"] else "HIGH",
        "action": "BLOCK",
        "status": "OPEN",
        "threat_score": random.uniform(70.0, 99.0),
        "source": "DEMO",
        "summary": f"[DEMO] Simulated {scenario} attack detected.",
        "explanation": ["Simulated demo injection", "source: DEMO"],
        "model1_score": random.uniform(60.0, 95.0),
        "model2_score": random.uniform(0.6, 0.95),
        "model3_score": random.uniform(50.0, 80.0),
        "model1_classification": scenario_label,
        "occurrence_count": 1,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "is_demo": True,
        "demo_scenario": scenario,
        "demo_run_id": demo_run_id
    })
    
    from app.services.websocket.connection_manager import get_websocket_hub
    hub = get_websocket_hub()
    
    # Broadcast new packets for the live dashboard chart
    for packet in packets_to_insert:
        await hub.queue_packet(packet)
        
    await hub.broadcast("new_threat", {"alert_id": alert_id})
    await hub.broadcast("demo_started", {"demo_run_id": demo_run_id})
    
    from app.services.threat_response.stats_service import get_full_dashboard_stats
    stats = await get_full_dashboard_stats(packet_repo=packet_repo, alert_repo=alert_repo)
    await hub.broadcast("stats_update", stats)
    
    return {
        "status": "success", 
        "scenario": scenario, 
        "packets_injected": num_packets, 
        "alert_id": alert_id,
        "demo_run_id": demo_run_id
    }


@router.delete("/reset")
async def reset_demo(
    run_id: str,
    packet_repo: PacketRepository = Depends(get_packet_repo),
    firewall_repo: FirewallActionRepository = Depends(get_firewall_action_repo),
    alert_repo: ThreatAlertRepository = Depends(get_threat_alert_repo)
):
    check_demo_mode()
    
    from app.database.client import db_has_demo_columns
    if not db_has_demo_columns():
        from app.repositories.base import _in_memory_demo_store
        for table in ["packets", "threat_alerts", "firewall_actions"]:
            if table in _in_memory_demo_store:
                _in_memory_demo_store[table] = [
                    row for row in _in_memory_demo_store[table]
                    if str(row.get("demo_run_id")) != run_id
                ]
    else:
        # Delete from all demo-affected tables
        await packet_repo._db.table("packets").delete().eq("demo_run_id", run_id).execute()
        await alert_repo._db.table("threat_alerts").delete().eq("demo_run_id", run_id).execute()
        await firewall_repo._db.table("firewall_actions").delete().eq("demo_run_id", run_id).execute()
    
    from app.services.websocket.connection_manager import get_websocket_hub
    hub = get_websocket_hub()
    await hub.broadcast("demo_reset", {"demo_run_id": run_id})
    
    from app.services.threat_response.stats_service import get_full_dashboard_stats
    stats = await get_full_dashboard_stats(packet_repo=packet_repo, alert_repo=alert_repo)
    await hub.broadcast("stats_update", stats)
    
    return {"status": "success", "demo_run_id": run_id}
