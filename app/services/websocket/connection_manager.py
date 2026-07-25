from datetime import datetime, timezone
import asyncio
import logging
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
