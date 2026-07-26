from datetime import datetime, timezone
import asyncio
import logging
from collections import deque
from typing import Set, List, Optional
from fastapi import WebSocket

from app.database.client import get_db_client
from app.repositories.repositories import ThreatAlertRepository, PacketRepository

logger = logging.getLogger("cybersentinel.services.websocket")

class WebSocketHub:
    def __init__(self) -> None:
        self.active_connections: Set[WebSocket] = set()
        
        # Connection Metrics
        self.packets_sent = 0
        self.threats_sent = 0
        self.last_broadcast: Optional[str] = None
        
        # Packet batching queue — hard cap to prevent memory growth
        self.packet_queue: List[dict] = []
        self._queue_lock = asyncio.Lock()
        self._PACKET_QUEUE_MAX = 500   # visible limit across all connected clients
        self._BATCH_SIZE = 50          # packets per WebSocket push
        self._analysis_context: deque[dict] = deque(maxlen=20)

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info("Client connected to unified WebSocket hub. Total: %d", len(self.active_connections))
        
        # Immediately push initial state snapshot
        await self._send_initial_state(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("Client disconnected from unified WebSocket hub. Remaining: %d", len(self.active_connections))

    async def broadcast(self, event_type: str, payload: dict, event_version: str = "1.0") -> None:
        """Broadcast a message using the envelope schema to all active connections."""
        if event_type == "packet_analysis_update":
            self._remember_analysis_context(payload)
        if not self.active_connections:
            return
            
        message = {
            "event_type": event_type,
            "event_version": event_version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload
        }
        
        # Update metrics
        if event_type == "packet_batch":
            self.packets_sent += len(payload.get("packets", []))
        elif event_type in ("new_threat", "alert_updated", "alert_resolved"):
            self.threats_sent += 1
            
        self.last_broadcast = message["timestamp"]

        disconnected = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception as exc:
                logger.error("Failed to send message to client: %s", exc)
                disconnected.append(connection)
                
        for connection in disconnected:
            await self.disconnect(connection)

    def _remember_analysis_context(self, payload: dict) -> None:
        """Retain bounded sanitized evidence already published to live clients."""
        flow_id = payload.get("flow_id")
        if not flow_id:
            return
        analysis_status = str(payload.get("analysis_status") or "").lower()
        if analysis_status not in {"complete", "partial", "failed"}:
            return
        session_id = None
        flow_context: dict = {}
        try:
            from app.services.packet_capture.capture_service import (
                get_capture_service,
            )

            capture_service = get_capture_service()
            session_id = capture_service.get_status().get("session_id")
            candidate_flows = [
                *capture_service.flow_manager.get_active_flows(),
                *capture_service.flow_manager.get_recent_completed(20),
            ]
            matching_flow = next(
                (
                    flow
                    for flow in candidate_flows
                    if str(getattr(flow, "flow_id", "")) == str(flow_id)
                ),
                None,
            )
            if matching_flow is not None:
                flow_context = matching_flow.model_dump()
        except Exception:
            pass

        model_results = payload.get("model_results")
        if not isinstance(model_results, dict):
            model_results = {}
        model1 = model_results.get("model1")
        model2 = model_results.get("model2")
        model3 = model_results.get("model3")
        record = {
            "session_id": session_id,
            "flow_id": flow_id,
            "packet_ids": list(payload.get("packet_ids") or [])[:8],
            "analysis_status": analysis_status,
            "severity": payload.get("severity"),
            "ml_prediction": payload.get("ml_prediction"),
            "ml_confidence": payload.get("ml_confidence"),
            "anomaly_score": payload.get("anomaly_score"),
            "threat_score": payload.get("threat_score"),
            "action": payload.get("action"),
            "model3_available": payload.get("model3_available"),
            "model3_intelligence_score": payload.get(
                "model3_intelligence_score"
            ),
            "model1": model1 if isinstance(model1, dict) else None,
            "model2": model2 if isinstance(model2, dict) else None,
            "model3": model3 if isinstance(model3, dict) else None,
            "src_ip": flow_context.get("src_ip"),
            "dst_ip": flow_context.get("dst_ip"),
            "src_port": flow_context.get("src_port"),
            "dst_port": flow_context.get("dst_port"),
            "protocol": flow_context.get("protocol"),
            "total_packets": flow_context.get("total_packets"),
            "ended_at": (
                flow_context.get("ended_at")
                or flow_context.get("last_activity")
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        retained = [
            item
            for item in self._analysis_context
            if not (
                item.get("flow_id") == flow_id
                and item.get("session_id") == session_id
            )
        ]
        self._analysis_context.clear()
        self._analysis_context.extend(retained)
        self._analysis_context.append(record)

    def get_recent_analysis_context(
        self,
        limit: int = 10,
        session_id: Optional[str] = None,
    ) -> list[dict]:
        """Return newest bounded live-analysis evidence for Copilot context."""
        records = list(reversed(self._analysis_context))
        if session_id:
            records = [
                item
                for item in records
                if item.get("session_id") == session_id
            ]
        return records[: max(min(limit, 20), 0)]

    async def queue_packet(self, packet_data: dict) -> None:
        """Add a captured packet to the batching queue (bounded to 500)."""
        async with self._queue_lock:
            if len(self.packet_queue) >= self._PACKET_QUEUE_MAX:
                # Drop oldest to maintain hard cap
                self.packet_queue.pop(0)
            self.packet_queue.append(packet_data)

    async def run_packet_batch_loop(self) -> None:
        """Background loop broadcasting packet batches every 1 second."""
        while True:
            try:
                await asyncio.sleep(1.0)
                async with self._queue_lock:
                    if not self.packet_queue:
                        continue
                    # Take the latest batch up to self._BATCH_SIZE packets
                    batch = self.packet_queue[-self._BATCH_SIZE:]
                    self.packet_queue.clear()
                    
                await self.broadcast("packet_batch", {"packets": batch})
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in packet batching loop: %s", e)

    async def run_heartbeat_loop(self) -> None:
        """Background loop emitting heartbeats every 30 seconds."""
        while True:
            try:
                await asyncio.sleep(30.0)
                heartbeat = {
                    "event_type": "heartbeat",
                    "event_version": "1.0",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "payload": {}
                }
                disconnected = []
                for connection in list(self.active_connections):
                    try:
                        await connection.send_json(heartbeat)
                    except Exception:
                        disconnected.append(connection)
                for connection in disconnected:
                    await self.disconnect(connection)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in heartbeat loop: %s", e)

    async def _send_initial_state(
        self, websocket: WebSocket, access_token: Optional[str] = None
    ) -> None:
        """Fetch and push the complete initial state snapshot on client connection."""
        try:
            if not access_token:
                logger.info("Initial database snapshot skipped without user token")
                return
            db = await get_db_client(access_token=access_token)
            alert_repo = ThreatAlertRepository(db)
            packet_repo = PacketRepository(db)
            
            # Fetch stats
            stats = await alert_repo.get_stats()
            
            # Fetch latest 10 alerts
            alerts_data, _ = await alert_repo.get_all(page=1, page_size=10)
            
            # Fetch latest 20 packets
            packets_data, _ = await packet_repo.list(order_by="captured_at", descending=True, page=1, page_size=20)
            
            snapshot = {
                "stats": stats,
                "latest_alerts": alerts_data,
                "latest_packets": packets_data
            }
            
            message = {
                "event_type": "initial_state",
                "event_version": "1.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "payload": snapshot
            }
            await websocket.send_json(message)
            logger.info("Initial state snapshot sent successfully to client")
        except Exception as e:
            logger.error("Failed to send initial state to client: %s", e)

    def get_metrics(self) -> dict:
        return {
            "active_connections": len(self.active_connections),
            "packets_sent": self.packets_sent,
            "threats_sent": self.threats_sent,
            "last_broadcast": self.last_broadcast
        }

_websocket_hub = WebSocketHub()

def get_websocket_hub() -> WebSocketHub:
    return _websocket_hub
