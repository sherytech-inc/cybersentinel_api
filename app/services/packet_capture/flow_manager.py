"""
CyberSentinel — Flow Manager
==============================
Aggregates parsed packets into bidirectional network flows.

Design:
    - Flow key is canonical: sorted (IP, port) pairs + protocol
      so A→B and B→A map to the same flow.
    - 60-second timeout (inactivity OR max age) triggers finalization.
    - Background cleanup task runs every N seconds.
    - Finalized flows are passed to FeatureExtractor automatically.

This is the most critical component in the ingestion pipeline.
Incorrect flow aggregation → incorrect features → incorrect predictions.
"""

import asyncio
import ipaddress
import logging
import time
import uuid
from collections import OrderedDict, deque
from datetime import datetime, timezone
from typing import Optional

from app.core.config import get_settings
from app.schemas.flow import FlowStateResponse, CompletedFlowResponse, ParsedPacket
from .feature_extractor import FeatureExtractor, detect_external_ip

from app.database.client import get_db_client
from app.services.model_rf import RandomForestService
from app.services.model_if import IsolationForestService
from app.services.preprocessor import DataPreprocessor
from app.scoring.threat_score import compute_threat_score
from app.scoring.severity import classify_severity
from app.schemas.decision import Model1Input, Model2Input
from app.repositories.repositories import PacketRepository

logger = logging.getLogger("cybersentinel.flow_manager")


def _is_public_intelligence_target(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False



class _FlowState:
    """
    Internal mutable state for an active network flow.
    NOT a Pydantic model — this is performance-critical mutable state.
    """
    __slots__ = (
        "flow_id", "initiator_ip", "responder_ip",
        "initiator_port", "responder_port", "protocol",
        "first_packet_time", "last_packet_time",
        "fwd_packet_lengths", "bwd_packet_lengths",
        "all_packet_lengths", "inter_arrival_times",
        "destination_port", "_prev_timestamp",
        "packet_ids", "analysis_pending", "analysis_dirty",
        "last_analysis_time", "last_analysis_packet_count", "final_requested",
    )

    def __init__(
        self,
        flow_id: str,
        initiator_ip: str,
        responder_ip: str,
        initiator_port: int,
        responder_port: int,
        protocol: str,
        destination_port: int,
        first_timestamp: float,
    ):
        self.flow_id = flow_id
        self.initiator_ip = initiator_ip
        self.responder_ip = responder_ip
        self.initiator_port = initiator_port
        self.responder_port = responder_port
        self.protocol = protocol
        self.destination_port = destination_port
        self.first_packet_time = first_timestamp
        self.last_packet_time = first_timestamp
        self.fwd_packet_lengths: list[int] = []
        self.bwd_packet_lengths: list[int] = []
        self.all_packet_lengths: list[int] = []
        self.inter_arrival_times: list[float] = []
        self._prev_timestamp = first_timestamp
        self.packet_ids: list[str] = []
        self.analysis_pending = False
        self.analysis_dirty = False
        self.last_analysis_time = 0.0
        self.last_analysis_packet_count = 0
        self.final_requested = False

    def add_packet(self, packet: ParsedPacket, is_forward: bool, packet_id: str):
        """Add a packet to this flow."""
        length = packet.packet_length
        self.all_packet_lengths.append(length)
        self.packet_ids.append(packet_id)
        if self.analysis_pending:
            self.analysis_dirty = True

        if is_forward:
            self.fwd_packet_lengths.append(length)
        else:
            self.bwd_packet_lengths.append(length)

        # Inter-arrival time
        iat = packet.timestamp - self._prev_timestamp
        if iat >= 0:
            self.inter_arrival_times.append(iat)
        self._prev_timestamp = packet.timestamp
        self.last_packet_time = packet.timestamp

    def to_dict(self) -> dict:
        """Export state as dict for FeatureExtractor consumption."""
        return {
            "flow_id": self.flow_id,
            "src_ip": self.initiator_ip,
            "dst_ip": self.responder_ip,
            "src_port": self.initiator_port,
            "dst_port": self.responder_port,
            "protocol": self.protocol,
            "destination_port": self.destination_port,
            "first_packet_time": self.first_packet_time,
            "last_packet_time": self.last_packet_time,
            "fwd_packet_lengths": self.fwd_packet_lengths,
            "bwd_packet_lengths": self.bwd_packet_lengths,
            "all_packet_lengths": self.all_packet_lengths,
            "inter_arrival_times": self.inter_arrival_times,
            "packet_ids": self.packet_ids,
        }

    @property
    def total_packets(self) -> int:
        return len(self.fwd_packet_lengths) + len(self.bwd_packet_lengths)

    @property
    def duration(self) -> float:
        return self.last_packet_time - self.first_packet_time


def _make_flow_key(packet: ParsedPacket) -> str:
    """
    Create a canonical bidirectional flow key.
    Sorted so A→B and B→A produce the same key.
    """
    pair = sorted([
        (packet.src_ip, packet.src_port),
        (packet.dst_ip, packet.dst_port),
    ])
    return f"{pair[0][0]}:{pair[0][1]}-{pair[1][0]}:{pair[1][1]}-{packet.protocol}"


class FlowManager:
    """
    Manages active network flows and finalizes them on timeout.

    Usage:
        manager = FlowManager(feature_extractor)
        await manager.start_cleanup_loop()
        ...
        manager.add_packet(parsed_packet)
        ...
        await manager.stop_cleanup_loop()
    """

    def __init__(self, feature_extractor: FeatureExtractor):
        self._settings = get_settings()
        self._extractor = feature_extractor
        self._active_flows: OrderedDict[str, _FlowState] = OrderedDict()
        self._completed: deque[CompletedFlowResponse] = deque(
            maxlen=self._settings.RECENT_FLOWS_LIMIT
        )
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        self._finalized_count = 0
        self._jwt_token: Optional[str] = None
        self._session_id: Optional[str] = None
        self._reported_analysis_errors: set[str] = set()
        self._analysis_queue: asyncio.Queue = asyncio.Queue(
            maxsize=self._settings.ANALYSIS_QUEUE_MAX_SIZE
        )
        self._analysis_workers: list[asyncio.Task] = []
        self._accepting_analysis = False
        self._analysis_active = 0
        self._analysis_max_concurrency = 0
        self._analysis_max_queue_depth = 0
        self._analysis_completed = 0
        self._analysis_failed = 0
        self._analysis_dropped = 0
        self._analysis_completed_packets = 0
        self._analysis_partial_packets = 0
        self._analysis_failed_packets = 0
        self._analysis_deferred_packets = 0
        self._analysis_cancelled_packets = 0
        self._flows_analyzed = 0
        self._terminal_packet_ids: set[str] = set()
        self._packet_classifications: dict[str, str] = {}
        self._last_reliable_score: Optional[float] = None
        self._highest_severity: Optional[str] = None
        self._deferred_updates: list[tuple[str, list[str], str]] = []
        self._deferred_update_task: Optional[asyncio.Task] = None

    def set_jwt_token(self, token: Optional[str]):
        """Store the user JWT token to authenticate database writes."""
        self._jwt_token = token

    def set_session_context(self, session_id: Optional[str]):
        self._session_id = session_id

    @property
    def jwt_token(self) -> Optional[str]:
        return self._jwt_token

    @property
    def stats(self) -> dict:
        return {
            "active_flows": len(self._active_flows),
            "finalized_total": self._finalized_count,
            "recent_completed_buffer": len(self._completed),
            "analysis_queue_depth": self._analysis_queue.qsize(),
            "analysis_queue_capacity": self._analysis_queue.maxsize,
            "analysis_active": self._analysis_active,
            "analysis_workers": len(self._analysis_workers),
            "analysis_max_concurrency": self._analysis_max_concurrency,
            "analysis_max_queue_depth": self._analysis_max_queue_depth,
            "analysis_completed": self._analysis_completed,
            "analysis_failed": self._analysis_failed,
            "analysis_dropped": self._analysis_dropped,
            "analyzed_packets": (
                self._analysis_completed_packets + self._analysis_partial_packets
            ),
            "terminal_packets": len(self._terminal_packet_ids),
            "completed_packets": self._analysis_completed_packets,
            "partial_packets": self._analysis_partial_packets,
            "failed_packets": self._analysis_failed_packets,
            "deferred_packets": self._analysis_deferred_packets,
            "cancelled_packets": self._analysis_cancelled_packets,
            "flows_analyzed": self._flows_analyzed,
            "normal_packets": sum(v == "normal" for v in self._packet_classifications.values()),
            "suspicious_packets": sum(v == "suspicious" for v in self._packet_classifications.values()),
            "malicious_packets": sum(v == "malicious" for v in self._packet_classifications.values()),
            "unknown_packets": sum(v == "unknown" for v in self._packet_classifications.values()),
            "last_reliable_score": self._last_reliable_score,
            "highest_severity": self._highest_severity,
            "pending_packets": max(
                sum(len(flow.packet_ids) for flow in self._active_flows.values())
                - len(self._terminal_packet_ids), 0
            ),
        }

    def add_packet(self, packet: ParsedPacket, packet_id: str = "") -> str:
        """
        Add a parsed packet to the appropriate flow.
        Creates a new flow if none exists for this connection.
        """
        flow_key = _make_flow_key(packet)

        if flow_key in self._active_flows:
            flow = self._active_flows[flow_key]
            # Determine direction: is this packet from the initiator?
            is_forward = (
                packet.src_ip == flow.initiator_ip
                and packet.src_port == flow.initiator_port
            )
            flow.add_packet(packet, is_forward, packet_id)
            # Move to end of OrderedDict (LRU-style)
            self._active_flows.move_to_end(flow_key)
        else:
            # New flow — the first packet's source is the "initiator"
            flow = _FlowState(
                flow_id=f"{flow_key}:{uuid.uuid4()}",
                initiator_ip=packet.src_ip,
                responder_ip=packet.dst_ip,
                initiator_port=packet.src_port,
                responder_port=packet.dst_port,
                protocol=packet.protocol,
                destination_port=packet.dst_port,
                first_timestamp=packet.timestamp,
            )
            flow.add_packet(packet, is_forward=True, packet_id=packet_id)
            self._active_flows[flow_key] = flow

            logger.debug("New flow created: %s", flow_key)
        return flow.flow_id

    def _finalize_flow(self, flow: _FlowState, reason: str):
        """
        Finalize a flow: extract features and record completion.
        """
        flow.final_requested = True
        self._queue_flow_analysis(flow, final=True)

        # Record completion
        external_ip, is_internal = detect_external_ip(
            flow.initiator_ip, flow.responder_ip
        )

        completed = CompletedFlowResponse(
            flow_id=flow.flow_id,
            src_ip=flow.initiator_ip,
            dst_ip=flow.responder_ip,
            src_port=flow.initiator_port,
            dst_port=flow.responder_port,
            protocol=flow.protocol,
            fwd_packets=len(flow.fwd_packet_lengths),
            bwd_packets=len(flow.bwd_packet_lengths),
            fwd_bytes=sum(flow.fwd_packet_lengths),
            bwd_bytes=sum(flow.bwd_packet_lengths),
            total_packets=flow.total_packets,
            total_bytes=sum(flow.all_packet_lengths),
            duration_seconds=round(flow.duration, 6),
            started_at=datetime.fromtimestamp(
                flow.first_packet_time, tz=timezone.utc
            ).isoformat(),
            ended_at=datetime.fromtimestamp(
                flow.last_packet_time, tz=timezone.utc
            ).isoformat(),
            finalized_reason=reason,
            external_ip=external_ip,
            is_internal_only=is_internal,
        )

        self._completed.append(completed)
        self._finalized_count += 1

        logger.info(
            "Flow finalized | id=%s reason=%s pkts=%d duration=%.3fs ext_ip=%s",
            flow.flow_id, reason, flow.total_packets, flow.duration,
            external_ip or "internal",
        )

    def _queue_flow_analysis(self, flow: _FlowState, *, final: bool = False) -> None:
        if flow.analysis_pending:
            flow.analysis_dirty = True
            flow.final_requested = flow.final_requested or final
            return
        flow_dict = flow.to_dict()
        result = self._extractor.extract(flow_dict)
        packet_ids = [packet_id for packet_id in flow.packet_ids if packet_id]
        if not result:
            self._schedule_terminal_update(
                flow.flow_id, packet_ids, "failed", "Feature extraction failed"
            )
            return
        flow.analysis_pending = True
        flow.analysis_dirty = False
        flow.final_requested = final
        flow.last_analysis_time = time.time()
        flow.last_analysis_packet_count = flow.total_packets
        self._enqueue_analysis(result, flow_dict, packet_ids, flow.flow_id, flow)

    def _enqueue_analysis(
        self, result, fs: dict, packet_ids: list[str], flow_id: str,
        flow: Optional[_FlowState] = None,
    ):
        job = (result, fs, packet_ids, flow_id, flow)
        if not self._accepting_analysis:
            self._analysis_dropped += 1
            if flow:
                flow.analysis_pending = False
            self._schedule_terminal_update(
                flow_id, packet_ids, "cancelled", "Analysis cancelled"
            )
            return
        try:
            self._analysis_queue.put_nowait(job)
            self._analysis_max_queue_depth = max(
                self._analysis_max_queue_depth, self._analysis_queue.qsize()
            )
        except asyncio.QueueFull:
            self._analysis_dropped += 1
            if flow:
                flow.analysis_pending = False
            self._schedule_terminal_update(
                flow_id, packet_ids, "deferred", "Analysis deferred"
            )

    def _schedule_terminal_update(
        self, flow_id: str, packet_ids: list[str], status: str, severity: str
    ) -> None:
        self._deferred_updates.append((flow_id, packet_ids, status, severity))
        if not self._deferred_update_task or self._deferred_update_task.done():
            self._deferred_update_task = asyncio.create_task(
                self._flush_deferred_updates()
            )

    async def _flush_deferred_updates(self) -> None:
        await asyncio.sleep(0)
        updates = self._deferred_updates[:]
        self._deferred_updates.clear()
        for flow_id, packet_ids, status, severity in updates:
            await self._publish_analysis_update(
                flow_id, packet_ids, analysis_status=status, severity=severity,
            )

    async def _analysis_worker(self, worker_id: int) -> None:
        while True:
            job = await self._analysis_queue.get()
            result, fs, packet_ids, flow_id, flow = job
            self._analysis_active += 1
            self._analysis_max_concurrency = max(
                self._analysis_max_concurrency, self._analysis_active
            )
            try:
                await self._analyze_and_save_flow(
                    result, fs, packet_ids, flow_id
                )
                self._analysis_completed += 1
                self._flows_analyzed += 1
            except asyncio.CancelledError:
                self._analysis_failed += 1
                await self._publish_analysis_update(
                    flow_id, packet_ids,
                    analysis_status="cancelled",
                    severity="Analysis cancelled",
                )
                raise
            except Exception as exc:
                self._analysis_failed += 1
                await self._publish_analysis_update(
                    flow_id, packet_ids,
                    analysis_status="failed",
                    severity="Analysis incomplete",
                )
                logger.error(
                    "Analysis worker failed | worker=%d type=%s",
                    worker_id,
                    type(exc).__name__,
                )
            finally:
                if flow:
                    flow.analysis_pending = False
                self._analysis_active -= 1
                self._analysis_queue.task_done()
                if flow and flow.analysis_dirty and flow.final_requested:
                    if self._accepting_analysis:
                        self._queue_flow_analysis(flow, final=True)
                    else:
                        self._schedule_terminal_update(
                            flow.flow_id,
                            list(flow.packet_ids),
                            "cancelled",
                            "Analysis cancelled",
                        )

    async def _publish_analysis_update(
        self,
        flow_id: str,
        packet_ids: list[str],
        *,
        analysis_status: str,
        severity: str,
        analysis_res=None,
    ) -> None:
        if not packet_ids:
            return
        from app.services.websocket.connection_manager import get_websocket_hub
        payload = {
            "flow_id": flow_id,
            "packet_ids": packet_ids,
            "update_scope": "flow_packets",
            "analysis_status": analysis_status,
            "severity": severity,
        }
        if analysis_res is not None:
            payload.update({
                "ml_prediction": analysis_res.model1.classification.capitalize(),
                "ml_confidence": analysis_res.model1.anomaly_probability,
                "anomaly_score": analysis_res.model2.anomaly_score,
                "threat_score": analysis_res.final_score,
                "action": analysis_res.action,
                "model3_available": analysis_res.model3_available,
                "model3_intelligence_score": (
                    analysis_res.model3_intelligence_score
                ),
                "model_results": {
                    "model1": analysis_res.model1.model_dump(),
                    "model2": analysis_res.model2.model_dump(),
                    "model3": analysis_res.model3.model_dump() if analysis_res.model3 else None,
                },
            })
        new_ids = set(packet_ids) - self._terminal_packet_ids
        self._terminal_packet_ids.update(packet_ids)
        if analysis_status == "complete":
            self._analysis_completed_packets += len(new_ids)
        elif analysis_status == "partial":
            self._analysis_partial_packets += len(new_ids)
        elif analysis_status == "deferred":
            self._analysis_deferred_packets += len(new_ids)
        elif analysis_status == "cancelled":
            self._analysis_cancelled_packets += len(new_ids)
        else:
            self._analysis_failed_packets += len(new_ids)
        if analysis_status in {"complete", "partial"}:
            classification = str(
                getattr(getattr(analysis_res, "model1", None), "classification", "unknown")
            ).lower()
            if classification in {"benign", "safe"}:
                classification = "normal"
            if classification not in {"normal", "suspicious", "malicious"}:
                classification = "unknown"
            for packet_id in new_ids:
                self._packet_classifications[packet_id] = classification
            if analysis_res is not None:
                self._last_reliable_score = float(analysis_res.final_score)
                severity = str(analysis_res.severity or "UNKNOWN").upper()
                ranks = {"UNKNOWN": 0, "SAFE": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
                if ranks.get(severity, 0) >= ranks.get(self._highest_severity or "UNKNOWN", 0):
                    self._highest_severity = severity
        await get_websocket_hub().broadcast("packet_analysis_update", payload)
        self._debug_stage(
            flow_id,
            "event_published",
            analysis_status=analysis_status,
            packet_count=len(packet_ids),
        )

    async def _analyze_and_save_flow(
        self, result, fs: dict, packet_ids: list[str], flow_id: str
    ):
        """Run authoritative live analysis, publish it, then persist best-effort."""
        try:
            from app.services.intelligence import get_enrichment_service
            from app.api.analyze_routes import analyze_flow_internal
            from app.schemas.analyze import AnalyzeFlowRequest

            intel_service = get_enrichment_service()
            analysis_ip = result.external_ip or result.dst_ip
            body = AnalyzeFlowRequest(
                ip=analysis_ip,
                flow_features=result.features.model_dump(),
                session_id=self._session_id,
            )
            self._debug_stage(
                flow_id,
                "analysis_started",
                feature_count=len(body.flow_features),
                packet_count=len(packet_ids),
            )
            analysis_res = await analyze_flow_internal(
                body=body,
                intel_service=intel_service,
                threat_repo=None,
                client_ip="127.0.0.1",
                persist_result=False,
                intel_eligible=_is_public_intelligence_target(analysis_ip),
            )
            self._debug_stage(
                flow_id,
                "models_completed",
                analysis_status=analysis_res.analysis_status,
                model1_status="available",
                model2_status="available",
                model3_status=(
                    "available" if analysis_res.model3_available else "unavailable"
                ),
            )
            await self._publish_analysis_update(
                flow_id, packet_ids,
                analysis_status=analysis_res.analysis_status,
                severity=analysis_res.severity,
                analysis_res=analysis_res,
            )
            try:
                await self._persist_flow_analysis(
                    result=result,
                    flow_snapshot=fs,
                    packet_ids=packet_ids,
                    flow_id=flow_id,
                    analysis_res=analysis_res,
                )
            except Exception as exc:
                self._report_persistence_issue(
                    f"persistence:unexpected:{type(exc).__name__}"
                )
        except Exception as e:
            key = f"{type(e).__name__}:{e}"
            if key not in self._reported_analysis_errors:
                self._reported_analysis_errors.add(key)
                logger.error(
                    "Capture flow analysis unavailable | type=%s reason=%s",
                    type(e).__name__,
                    e,
                )
            raise

    def _debug_stage(self, flow_id: str, stage: str, **fields) -> None:
        if not self._settings.DEBUG:
            return
        details = " ".join(f"{key}={value}" for key, value in fields.items())
        logger.debug("Flow stage | flow_id=%s stage=%s %s", flow_id, stage, details)

    async def _persist_flow_analysis(
        self,
        *,
        result,
        flow_snapshot: dict,
        packet_ids: list[str],
        flow_id: str,
        analysis_res,
    ) -> None:
        """Persist an already-published analysis without affecting live state."""
        if not self._jwt_token:
            self._report_persistence_issue("persistence:token_unavailable")
            return
        try:
            from app.database.client import get_db_client
            db = await get_db_client(access_token=self._jwt_token)
        except Exception as exc:
            self._report_persistence_issue(
                f"persistence:client:{type(exc).__name__}"
            )
            return

        self._debug_stage(flow_id, "persistence_started")
        from app.repositories import (
            PacketRepository,
            ThreatAlertRepository,
            ThreatScoreRepository,
        )

        threat_repo = ThreatScoreRepository(db)
        try:
            await threat_repo.insert({
                "session_id": self._session_id,
                "source_ip": result.src_ip,
                "model1_prediction": analysis_res.model1.classification,
                "model1_confidence": analysis_res.model1.anomaly_probability,
                "model2_anomaly_score": analysis_res.model2.anomaly_score,
                "model3_intel_score": getattr(
                    analysis_res, "model3_intelligence_score", None
                ),
                "threat_score": analysis_res.final_score,
                "severity": analysis_res.severity,
                "recommendation": analysis_res.action,
                "reasoning": analysis_res.explanation,
                "model3_available": analysis_res.model3_available,
            })
        except Exception as exc:
            self._report_persistence_issue(
                f"persistence:threat_score:{type(exc).__name__}"
            )

        lengths = flow_snapshot.get("all_packet_lengths", [])
        fwd_lengths = flow_snapshot.get("fwd_packet_lengths", [])
        bwd_lengths = flow_snapshot.get("bwd_packet_lengths", [])
        packet_data = {
            "session_id": self._session_id,
            "flow_id": flow_id,
            "packet_ids": packet_ids[:100],
            "source_ip": result.src_ip,
            "destination_ip": result.dst_ip,
            "source_port": flow_snapshot.get("src_port"),
            "destination_port": flow_snapshot.get("dst_port"),
            "protocol": flow_snapshot.get("protocol"),
            "packet_size": sum(lengths) // len(lengths) if lengths else 0,
            "flow_duration": result.features.flow_duration,
            "fwd_packet_length_mean": (
                round(sum(fwd_lengths) / len(fwd_lengths), 4)
                if fwd_lengths else 0.0
            ),
            "bwd_packet_length_mean": (
                round(sum(bwd_lengths) / len(bwd_lengths), 4)
                if bwd_lengths else 0.0
            ),
            "ml_prediction": analysis_res.model1.classification.capitalize(),
            "ml_confidence": analysis_res.model1.anomaly_probability,
            "anomaly_score": analysis_res.model2.anomaly_score,
            "threat_score": analysis_res.final_score,
            "severity": analysis_res.severity,
            "analysis_status": analysis_res.analysis_status,
            "action": analysis_res.action,
            "model3_available": analysis_res.model3_available,
            "model3_intelligence_score": getattr(
                analysis_res, "model3_intelligence_score", None
            ),
        }
        try:
            inserted = await PacketRepository(db).insert(packet_data)
            if not inserted:
                self._report_persistence_issue("persistence:packet:not_saved")
        except Exception as exc:
            self._report_persistence_issue(
                f"persistence:packet:{type(exc).__name__}"
            )

        if analysis_res.severity in {"HIGH", "CRITICAL"}:
            try:
                from app.services.threat_response.alert_generator import AlertGenerator
                from app.services.threat_response.alert_service import AlertService
                alert_generator = AlertGenerator(
                    AlertService(ThreatAlertRepository(db))
                )
                await alert_generator.generate_alert({
                    "source_ip": result.src_ip,
                    "severity": analysis_res.severity,
                    "action": analysis_res.action,
                    "threat_score": analysis_res.final_score,
                    "explanation": analysis_res.explanation,
                    "trace_id": analysis_res.trace_id,
                    "model1_score": (
                        analysis_res.model1.anomaly_probability * 100
                    ),
                    "model2_score": analysis_res.model2.anomaly_score,
                    "model3_score": (
                        getattr(
                            analysis_res, "model3_intelligence_score", None
                        ) or 0.0
                    ),
                    "model1_classification": (
                        analysis_res.model1.classification
                    ),
                    "model2_severity": (
                        "HIGH" if analysis_res.model2.is_anomaly else "NORMAL"
                    ),
                    "model3_severity": (
                        analysis_res.model3.reputation.upper()
                        if analysis_res.model3_available and analysis_res.model3
                        else "UNAVAILABLE"
                    ),
                })
            except Exception as exc:
                self._report_persistence_issue(
                    f"persistence:alert:{type(exc).__name__}"
                )

        self._debug_stage(flow_id, "persistence_finished")

    def _report_persistence_issue(self, key: str) -> None:
        if key in self._reported_analysis_errors:
            return
        self._reported_analysis_errors.add(key)
        logger.warning("Live analysis persistence unavailable | reason=%s", key)


    def _cleanup_expired(self):
        """
        Check all active flows and finalize those that have timed out.
        Called by the background cleanup loop.
        """
        now = time.time()
        timeout = self._settings.FLOW_TIMEOUT_SECONDS
        expired_keys = []

        for key, flow in self._active_flows.items():
            inactive_time = now - flow.last_packet_time
            flow_age = now - flow.first_packet_time

            if inactive_time >= timeout:
                expired_keys.append((key, "timeout"))
            elif flow_age >= timeout:
                expired_keys.append((key, "max_age"))
            elif not flow.analysis_pending:
                first_eligible = (
                    flow.last_analysis_packet_count == 0
                    and (
                        flow.total_packets >= self._settings.FLOW_FIRST_ANALYSIS_PACKETS
                        or flow_age >= self._settings.FLOW_FIRST_ANALYSIS_AGE_SECONDS
                    )
                )
                refresh_eligible = (
                    flow.last_analysis_packet_count > 0
                    and flow.total_packets > flow.last_analysis_packet_count
                    and now - flow.last_analysis_time
                    >= self._settings.FLOW_REANALYSIS_INTERVAL_SECONDS
                )
                if first_eligible or refresh_eligible:
                    self._queue_flow_analysis(flow)

        for key, reason in expired_keys:
            flow = self._active_flows.pop(key)
            self._finalize_flow(flow, reason)

        if expired_keys:
            logger.info(
                "Cleanup: finalized %d flows, %d still active",
                len(expired_keys), len(self._active_flows),
            )

    async def _cleanup_loop(self):
        """Background loop that periodically cleans up expired flows."""
        interval = self._settings.FLOW_CLEANUP_INTERVAL
        while self._running:
            try:
                self._cleanup_expired()
            except Exception as e:
                logger.error("Flow cleanup error: %s", e)
            await asyncio.sleep(interval)

    async def start_cleanup_loop(self):
        """Start the background flow cleanup task."""
        if self._running:
            return
        self._running = True
        self._accepting_analysis = True
        self._analysis_active = 0
        self._analysis_max_concurrency = 0
        self._analysis_max_queue_depth = 0
        self._analysis_completed = 0
        self._analysis_failed = 0
        self._analysis_dropped = 0
        self._analysis_completed_packets = 0
        self._analysis_partial_packets = 0
        self._analysis_failed_packets = 0
        self._analysis_deferred_packets = 0
        self._analysis_cancelled_packets = 0
        self._flows_analyzed = 0
        self._terminal_packet_ids.clear()
        self._packet_classifications.clear()
        self._last_reliable_score = None
        self._highest_severity = None
        self._analysis_workers = [
            asyncio.create_task(self._analysis_worker(index))
            for index in range(self._settings.ANALYSIS_WORKER_COUNT)
        ]
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info(
            "Flow cleanup loop started (interval=%ds, timeout=%ds)",
            self._settings.FLOW_CLEANUP_INTERVAL,
            self._settings.FLOW_TIMEOUT_SECONDS,
        )

    async def stop_cleanup_loop(self):
        """Stop the cleanup loop and finalize all remaining flows."""
        self._running = False
        self._accepting_analysis = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None

        # Finalize all remaining active flows
        remaining = list(self._active_flows.keys())
        for key in remaining:
            flow = self._active_flows.pop(key)
            self._finalize_flow(flow, "manual_stop")

        queued_packet_ids: list[str] = []
        while not self._analysis_queue.empty():
            _, _, packet_ids, flow_id, flow = self._analysis_queue.get_nowait()
            queued_packet_ids.extend(
                list(flow.packet_ids) if flow is not None else packet_ids
            )
            if flow:
                flow.analysis_pending = False
            self._analysis_queue.task_done()
            self._analysis_dropped += 1
        for worker in self._analysis_workers:
            worker.cancel()
        if self._analysis_workers:
            await asyncio.gather(*self._analysis_workers, return_exceptions=True)
        self._analysis_workers.clear()
        if queued_packet_ids:
            await self._publish_analysis_update(
                "capture-stop",
                list(dict.fromkeys(queued_packet_ids)),
                analysis_status="cancelled",
                severity="Analysis cancelled",
            )
        if self._deferred_update_task:
            await asyncio.gather(self._deferred_update_task, return_exceptions=True)
            self._deferred_update_task = None
        if self._deferred_updates:
            await self._flush_deferred_updates()

        logger.info("Flow cleanup loop stopped. Finalized %d remaining flows.", len(remaining))

    def get_active_flows(self) -> list[FlowStateResponse]:
        """Return all currently active flows as response models."""
        result = []
        for flow in self._active_flows.values():
            external_ip, is_internal = detect_external_ip(
                flow.initiator_ip, flow.responder_ip
            )
            result.append(FlowStateResponse(
                flow_id=flow.flow_id,
                src_ip=flow.initiator_ip,
                dst_ip=flow.responder_ip,
                src_port=flow.initiator_port,
                dst_port=flow.responder_port,
                protocol=flow.protocol,
                fwd_packets=len(flow.fwd_packet_lengths),
                bwd_packets=len(flow.bwd_packet_lengths),
                fwd_bytes=sum(flow.fwd_packet_lengths),
                bwd_bytes=sum(flow.bwd_packet_lengths),
                total_packets=flow.total_packets,
                total_bytes=sum(flow.all_packet_lengths),
                duration_seconds=round(flow.duration, 6),
                started_at=datetime.fromtimestamp(
                    flow.first_packet_time, tz=timezone.utc
                ).isoformat(),
                last_activity=datetime.fromtimestamp(
                    flow.last_packet_time, tz=timezone.utc
                ).isoformat(),
                external_ip=external_ip,
                is_internal_only=is_internal,
            ))
        return result

    def get_recent_completed(self, limit: int = 50) -> list[CompletedFlowResponse]:
        """Return most recently finalized flows (newest first)."""
        items = list(self._completed)
        items.reverse()
        return items[:limit]
