"""
CyberSentinel — Capture Service
================================
Async TShark/PyShark packet capture engine.

Supports two modes:
    1. LIVE capture — requires TShark + root/sudo on macOS
    2. PCAP replay — loads a .pcap file, no special permissions needed
       (more important for FYP demos)

Architecture:
    CaptureService
        → PacketParser.parse(raw_packet)
        → FlowManager.add_packet(parsed_packet)
        → FeatureExtractor (called automatically when flows finalize)

The capture runs in a background asyncio task and NEVER blocks FastAPI.
"""

import asyncio
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from app.core.config import get_settings
from .packet_parser import PacketParser
from .flow_manager import FlowManager
from .feature_extractor import FeatureExtractor
from app.services.capture_executables import resolve_capture_executable

logger = logging.getLogger("cybersentinel.capture_service")


class CaptureState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    REPLAY = "replay"
    STOPPING = "stopping"
    ERROR = "error"


class CaptureService:
    """
    Singleton capture engine. Created once at app startup, reused for all requests.

    Usage:
        service = CaptureService()
        await service.start_live("en0")      # or
        await service.start_pcap("attack.pcap")
        ...
        await service.stop()
    """

    def __init__(self):
        self._settings = get_settings()
        self._state = CaptureState.STOPPED
        self._error_message: Optional[str] = None
        self._packets_captured = 0
        self._started_at: Optional[str] = None
        self._started_monotonic: Optional[float] = None

        # Pipeline components
        self._parser = PacketParser()
        self._extractor = FeatureExtractor(
            max_recent=self._settings.RECENT_FEATURES_LIMIT
        )
        self._flow_manager = FlowManager(self._extractor)

        # Threading & Async Queue
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._queue: Optional[asyncio.Queue] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._active_capture = None
        self._consumer_task: Optional[asyncio.Task] = None
        self._health_check_task: Optional[asyncio.Task] = None
        self._live_stats_task: Optional[asyncio.Task] = None
        self._tshark_path: Optional[str] = None
        self._dumpcap_path: Optional[str] = None
        self._consumer_ready: Optional[asyncio.Event] = None
        self._subprocess_ready: Optional[asyncio.Event] = None
        self._first_packet_received: Optional[asyncio.Event] = None
        self._sample_live_event_logged = False
        self._interface: Optional[str] = None
        self._session_id: Optional[str] = None

    @property
    def state(self) -> CaptureState:
        return self._state

    @property
    def flow_manager(self) -> FlowManager:
        return self._flow_manager

    @property
    def feature_extractor(self) -> FeatureExtractor:
        return self._extractor

    def get_status(self) -> dict:
        """Full status snapshot for the /capture/status endpoint."""
        mapped_state = self._state.value
        flow_stats = self._flow_manager.stats
        analyzed_packets = flow_stats["analyzed_packets"]

        return {
            "state": mapped_state,
            "error": self._error_message,
            "interface": self._interface or self._settings.CAPTURE_INTERFACE,
            "session_id": self._session_id,
            "started_at": self._started_at,
            "packets_captured": self._packets_captured,
            "packets_per_second": round(
                self._packets_captured / max(time.monotonic() - self._started_monotonic, 0.001),
                2,
            ) if self._started_monotonic else 0.0,
            "parser": self._parser.stats,
            "flows": flow_stats,
            "analysis": {
                "analyzed_packets": analyzed_packets,
                "pending_packets": max(
                    self._packets_captured
                    - analyzed_packets
                    - flow_stats["failed_packets"]
                    - flow_stats["deferred_packets"]
                    - flow_stats["cancelled_packets"],
                    0,
                ) if self._state != CaptureState.STOPPED else 0,
                "completed_packets": flow_stats["completed_packets"],
                "partial_packets": flow_stats["partial_packets"],
                "failed_packets": flow_stats["failed_packets"],
                "deferred_packets": flow_stats["deferred_packets"],
                "cancelled_packets": flow_stats["cancelled_packets"],
                "flows_analyzed": flow_stats["flows_analyzed"],
                "queue_depth": flow_stats["analysis_queue_depth"],
                "queue_capacity": flow_stats["analysis_queue_capacity"],
                "active_workers": flow_stats["analysis_active"],
                "max_concurrency": flow_stats["analysis_max_concurrency"],
            },
            "features": self._extractor.stats,
            "config": {
                "bpf_filter": self._settings.CAPTURE_BPF_FILTER,
                "flow_timeout_seconds": self._settings.FLOW_TIMEOUT_SECONDS,
            },
        }

    def _set_error_state(self, message: str) -> None:
        self._state = CaptureState.ERROR
        self._error_message = message
        logger.error("Capture error set: %s", message)

    def _set_idle_state(self) -> None:
        self._state = CaptureState.STOPPED
        logger.info("Replay finished and state set to STOPPED.")

    async def _packet_consumer_loop(self) -> None:
        """Consumer task running on the main event loop."""
        if self._consumer_ready:
            self._consumer_ready.set()
        logger.info("Packet consumer task started.")
        while True:
            try:
                if self._queue is None:
                    await asyncio.sleep(0.1)
                    continue
                parsed = await self._queue.get()
                try:
                    packet_id = str(uuid.uuid4())
                    flow_id = self._flow_manager.add_packet(
                        parsed, packet_id=packet_id
                    )
                    self._packets_captured += 1
                    from app.services.websocket.connection_manager import get_websocket_hub
                    live_packet = {
                        "id": packet_id,
                        "packet_id": packet_id,
                        "flow_id": flow_id,
                        "session_id": self._session_id,
                        "source_ip": parsed.src_ip,
                        "destination_ip": parsed.dst_ip,
                        "source_port": parsed.src_port,
                        "destination_port": parsed.dst_port,
                        "protocol": parsed.protocol,
                        "packet_size": parsed.packet_length,
                        "captured_at": datetime.fromtimestamp(
                            parsed.timestamp, tz=timezone.utc
                        ).isoformat(),
                        "ml_prediction": "Pending",
                        "severity": "Analysis pending",
                        "analysis_status": "pending",
                    }
                    await get_websocket_hub().queue_packet(live_packet)
                    if not self._sample_live_event_logged:
                        logger.info(
                            "Sample live packet queued | protocol=%s size=%s",
                            parsed.protocol,
                            parsed.packet_length,
                        )
                        self._sample_live_event_logged = True
                except Exception as exc:
                    logger.exception(
                        "Packet consumer skipped packet after %s",
                        type(exc).__name__,
                    )
                finally:
                    self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception("Error in packet consumer loop: %s", e)

    async def _health_check_loop(self) -> None:
        """Monitors the capture for the first 10 seconds to ensure it is actually receiving packets."""
        try:
            if self._consumer_ready:
                await self._consumer_ready.wait()
            if self._first_packet_received:
                try:
                    await asyncio.wait_for(self._first_packet_received.wait(), timeout=10)
                    logger.info("Capture health confirmed by first packet.")
                    return
                except TimeoutError:
                    pass
            if self._state == CaptureState.RUNNING and self._packets_captured == 0:
                logger.error("Health check failed: No packets received after 10 seconds.")
                await self._cleanup_failed_start(
                    "Capture subprocess is running but no matching packets were received."
                )
        except asyncio.CancelledError:
            pass

    async def _live_stats_broadcast_loop(self) -> None:
        """Broadcast authenticated dashboard snapshots at a low fixed cadence."""
        try:
            from app.services.websocket.connection_manager import get_websocket_hub
            from app.services.threat_response.stats_service import get_full_dashboard_stats
            from app.database.client import get_db_client
            from app.repositories import PacketRepository, ThreatAlertRepository
            from app.services.reporting.analytics_service import AnalyticsService
            hub = get_websocket_hub()
            while self._state in (CaptureState.RUNNING, CaptureState.REPLAY):
                try:
                    token = self._flow_manager.jwt_token
                    if token:
                        db = await get_db_client(access_token=token)
                        stats = await get_full_dashboard_stats(
                            packet_repo=PacketRepository(db),
                            alert_repo=ThreatAlertRepository(db),
                            analytics=AnalyticsService(db),
                        )
                        await hub.broadcast("stats_update", stats)
                except Exception as e:
                    logger.debug(
                        "Live stats unavailable | type=%s", type(e).__name__
                    )
                await asyncio.sleep(self._settings.LIVE_STATS_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            pass

    async def start_live(self, interface: Optional[str] = None, jwt_token: Optional[str] = None,
                         session_id: Optional[str] = None):
        """
        Start live packet capture via TShark/PyShark inside a background thread.

        Args:
            interface: Network interface (default: from config, typically en0)
        """
        if self._state == CaptureState.STARTING and not self._has_live_work():
            await self._cleanup_failed_start("Recovered stale capture startup state.")

        if self._state in (CaptureState.RUNNING, CaptureState.REPLAY, CaptureState.STARTING):
            raise RuntimeError(f"Capture already running (state={self._state.value})")

        self._state = CaptureState.STARTING
        try:
            from app.services.capture_capability_service import CaptureCapabilityService
            cap_service = CaptureCapabilityService()
            caps = cap_service.get_capabilities()
            if not caps.capture_supported:
                raise RuntimeError(
                    "Missing capture capabilities (TShark, dumpcap, or permissions)."
                )

            self._tshark_path = resolve_capture_executable(
                "tshark", self._settings.TSHARK_EXECUTABLE
            ).path
            self._dumpcap_path = resolve_capture_executable(
                "dumpcap", self._settings.DUMPCAP_EXECUTABLE
            ).path

            import pyshark
            session_id = session_id or str(uuid.uuid4())
            self._flow_manager.set_jwt_token(jwt_token)
            self._flow_manager.set_session_context(session_id)
            self._session_id = session_id
            iface = interface or self._settings.CAPTURE_INTERFACE
            self._interface = iface
            bpf = self._settings.CAPTURE_BPF_FILTER
            self._reset_counters()
            self._queue = asyncio.Queue()
            self._loop = asyncio.get_running_loop()
            self._consumer_ready = asyncio.Event()
            self._subprocess_ready = asyncio.Event()
            self._first_packet_received = asyncio.Event()
            self._stop_event.clear()

            logger.info(
                "Starting live capture on interface=%s tshark=%s dumpcap=%s",
                iface,
                self._tshark_path,
                self._dumpcap_path,
            )
            await self._flow_manager.start_cleanup_loop()
            self._consumer_task = asyncio.create_task(self._packet_consumer_loop())
            self._thread = threading.Thread(
                target=self._live_sniff_thread,
                args=(iface, bpf, self._loop),
                daemon=True,
            )
            self._thread.start()
            await self._wait_until_live_ready()
            self._health_check_task = asyncio.create_task(self._health_check_loop())
            self._live_stats_task = asyncio.create_task(self._live_stats_broadcast_loop())
            from datetime import datetime, timezone
            self._started_at = datetime.now(timezone.utc).isoformat()
            self._started_monotonic = time.monotonic()
            self._state = CaptureState.RUNNING
            self._error_message = None
        except Exception as exc:
            message = str(exc) or type(exc).__name__
            await self._cleanup_failed_start(message)
            raise RuntimeError(message) from exc

    async def _wait_until_live_ready(self, timeout: float = 5.0) -> None:
        """Wait until the consumer and a real PyShark subprocess are alive."""
        if not self._consumer_ready:
            raise RuntimeError("Packet consumer readiness was not initialized.")
        await asyncio.wait_for(self._consumer_ready.wait(), timeout=timeout)
        if not self._subprocess_ready:
            raise RuntimeError("Capture subprocess readiness was not initialized.")
        await asyncio.wait_for(self._subprocess_ready.wait(), timeout=timeout)
        if not self._thread or not self._thread.is_alive():
            raise RuntimeError("Capture consumer exited during startup.")
        logger.info("Capture subprocess and packet consumer are ready.")

    def _has_live_work(self) -> bool:
        return bool(
            (self._thread and self._thread.is_alive())
            or (self._consumer_task and not self._consumer_task.done())
            or self._active_capture
        )

    async def _cleanup_failed_start(self, message: str) -> None:
        self._stop_event.set()
        if self._active_capture:
            try:
                self._active_capture.close()
            except Exception:
                pass
            self._active_capture = None
        for attr in ("_health_check_task", "_live_stats_task", "_consumer_task"):
            task = getattr(self, attr, None)
            if task and task is not asyncio.current_task():
                task.cancel()
            setattr(self, attr, None)
        if self._thread and self._thread is not threading.current_thread():
            await asyncio.to_thread(self._thread.join, timeout=1.0)
        self._thread = None
        await self._flow_manager.stop_cleanup_loop()
        self._queue = None
        self._loop = None
        self._consumer_ready = None
        self._subprocess_ready = None
        self._first_packet_received = None
        self._started_at = None
        self._started_monotonic = None
        self._state = CaptureState.STOPPED
        self._error_message = message
        logger.error("Capture startup failed: %s", message)

    async def start_pcap(self, file_path: str, jwt_token: Optional[str] = None,
                         session_id: Optional[str] = None):
        """
        Replay packets from a .pcap file in a background thread.
        No sudo required — ideal for demos and testing.
        """
        if self._state in (CaptureState.RUNNING, CaptureState.REPLAY, CaptureState.STARTING):
            raise RuntimeError(f"Capture already running (state={self._state.value})")

        self._state = CaptureState.STARTING

        session_id = session_id or str(uuid.uuid4())
        self._flow_manager.set_jwt_token(jwt_token)
        self._flow_manager.set_session_context(session_id)
        self._session_id = session_id

        try:
            import pyshark
        except ImportError:
            self._state = CaptureState.ERROR
            self._error_message = "pyshark not installed. Run: pip install pyshark"
            raise RuntimeError(self._error_message)

        import os
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found: {file_path}")

        self._reset_counters()
        self._state = CaptureState.REPLAY
        self._error_message = None
        from datetime import datetime, timezone
        self._started_at = datetime.now(timezone.utc).isoformat()
        self._started_monotonic = time.monotonic()
        self._queue = asyncio.Queue()
        self._loop = asyncio.get_running_loop()
        self._stop_event.clear()

        logger.info("Starting PCAP replay thread: %s", file_path)

        # Start the flow cleanup loop
        await self._flow_manager.start_cleanup_loop()

        # Start packet consumer loop
        self._consumer_task = asyncio.create_task(self._packet_consumer_loop())

        # Start replay thread
        self._thread = threading.Thread(
            target=self._pcap_replay_thread,
            args=(file_path, self._loop),
            daemon=True
        )
        self._thread.start()
        
        # Start live stats broadcasting
        self._live_stats_task = asyncio.create_task(self._live_stats_broadcast_loop())

    async def stop(self):
        """Stop capture/replay and finalize all active flows."""
        if self._state not in (CaptureState.RUNNING, CaptureState.REPLAY, CaptureState.STARTING):
            return

        self._state = CaptureState.STOPPING
        logger.info("Stopping capture...")

        # 1. Trigger stop events and close active pyshark captures
        self._stop_event.set()
        if self._active_capture:
            try:
                self._active_capture.close()
            except Exception:
                pass
            self._active_capture = None

        # 2. Cancel tasks
        if getattr(self, '_health_check_task', None):
            self._health_check_task.cancel()
            self._health_check_task = None
            
        if getattr(self, '_live_stats_task', None):
            self._live_stats_task.cancel()
            self._live_stats_task = None
            
        if self._consumer_task:
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except asyncio.CancelledError:
                pass
            self._consumer_task = None

        # 3. Wait for sniffing thread to exit
        if self._thread:
            await asyncio.to_thread(self._thread.join, timeout=2.0)
            self._thread = None

        # 4. Stop flow cleanup and finalize remaining flows
        await self._flow_manager.stop_cleanup_loop()

        self._state = CaptureState.STOPPED
        from app.services.websocket.connection_manager import get_websocket_hub
        await get_websocket_hub().broadcast(
            "stats_update",
            {"snapshot": {"capture_diagnostics": self.get_status()}},
        )
        logger.info(
            "Capture stopped. Total packets: %d", self._packets_captured
        )

    def _live_sniff_thread(self, interface: str, bpf_filter: str, loop: asyncio.AbstractEventLoop) -> None:
        """Background thread sniffing live packets from network interface."""
        import pyshark
        try:
            service = self

            class ReadyLiveCapture(pyshark.LiveCapture):
                def _created_new_process(self, parameters, process, process_name="TShark"):
                    super()._created_new_process(parameters, process, process_name)
                    logger.info(
                        "%s subprocess started pid=%s returncode=%s",
                        process_name,
                        process.pid,
                        process.returncode,
                    )
                    if process_name == "TShark" and service._subprocess_ready:
                        loop.call_soon_threadsafe(service._subprocess_ready.set)

            self._active_capture = ReadyLiveCapture(
                interface=interface,
                bpf_filter=bpf_filter,
                use_json=True,
                tshark_path=self._tshark_path,
            )
            logger.info("PyShark packet iterator starting.")
            for raw_packet in self._active_capture.sniff_continuously():
                if self._stop_event.is_set():
                    break
                if self._first_packet_received and not self._first_packet_received.is_set():
                    loop.call_soon_threadsafe(self._first_packet_received.set)
                    logger.info("First raw packet received from PyShark.")
                try:
                    parsed = self._parser.parse(raw_packet)
                except Exception as exc:
                    logger.exception(
                        "Packet parse failed with %s; skipping packet",
                        type(exc).__name__,
                    )
                    continue
                if parsed is not None:
                    loop.call_soon_threadsafe(self._queue.put_nowait, parsed)
            
            if not self._stop_event.is_set():
                message = "Capture subprocess exited unexpectedly."
                statuses = [
                    {"pid": process.pid, "returncode": process.returncode}
                    for process in getattr(self._active_capture, "_running_processes", ())
                ]
                stderr_line = str(
                    getattr(self._active_capture, "_last_error_line", "") or ""
                )[:500]
                logger.error(
                    "%s processes=%s stderr=%s", message, statuses, stderr_line
                )
                loop.call_soon_threadsafe(
                    lambda failure=message: asyncio.create_task(
                        self._cleanup_failed_start(failure)
                    )
                )
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            stderr_line = str(
                getattr(self._active_capture, "_last_error_line", "") or ""
            )[:500]
            logger.exception(
                "Error in live sniff thread: %s stderr=%s", message, stderr_line
            )
            loop.call_soon_threadsafe(
                lambda failure=message: asyncio.create_task(
                    self._cleanup_failed_start(failure)
                )
            )
        finally:
            if self._active_capture:
                try:
                    self._active_capture.close()
                except Exception:
                    pass
                self._active_capture = None

    def _pcap_replay_thread(self, file_path: str, loop: asyncio.AbstractEventLoop) -> None:
        """Background thread replaying packets from a PCAP file."""
        import pyshark
        try:
            self._active_capture = pyshark.FileCapture(
                file_path,
                keep_packets=False,
            )
            for raw_packet in self._active_capture:
                if self._stop_event.is_set():
                    break
                parsed = self._parser.parse(raw_packet)
                if parsed is not None:
                    loop.call_soon_threadsafe(self._queue.put_nowait, parsed)
            
            logger.info("PCAP replay thread finished parsing file.")
            loop.call_soon_threadsafe(self._set_idle_state)
        except Exception as e:
            loop.call_soon_threadsafe(self._set_error_state, str(e))
        finally:
            if self._active_capture:
                try:
                    self._active_capture.close()
                except Exception:
                    pass
                self._active_capture = None

            # Clean up the temp PCAP file
            import os
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info("Removed temporary PCAP file: %s", file_path)
            except Exception as e:
                logger.error("Failed to remove PCAP file %s: %s", file_path, e)

    def _reset_counters(self):
        """Reset all counters for a fresh capture session."""
        self._packets_captured = 0
        self._parser.reset_stats()
        self._error_message = None
        self._started_at = None
        self._started_monotonic = None
        self._sample_live_event_logged = False



# ── Singleton + FastAPI Dependency ────────────────────────────────────────────

_capture_service: Optional[CaptureService] = None


def init_capture_service() -> CaptureService:
    """Initialize the global capture service singleton. Called during app lifespan."""
    global _capture_service
    _capture_service = CaptureService()
    return _capture_service


def get_capture_service() -> CaptureService:
    """FastAPI dependency — returns the capture service singleton."""
    if _capture_service is None:
        raise RuntimeError("Capture service not initialized. Check app lifespan.")
    return _capture_service
