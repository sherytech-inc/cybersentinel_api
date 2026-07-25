"""
CyberSentinel — Feature Extraction Schemas
==========================================
Pydantic models for the extracted feature vectors that feed Models 1 & 2.
The field names here MUST exactly match Model 2's FEATURE_COLUMNS
(verified against both model artifacts).
"""

from typing import Optional

from pydantic import BaseModel, Field


class ExtractedFeatures(BaseModel):
    """
    The 11-field feature vector that maps 1:1 to model training schema.
    """
    flow_duration: float = Field(..., ge=0, description="Duration in seconds")
    src_pkts: int = Field(..., ge=0, description="Packets: initiator → responder")
    dst_pkts: int = Field(..., ge=0, description="Packets: responder → initiator")
    src_bytes: int = Field(..., ge=0, description="Total bytes: initiator → responder")
    dst_bytes: int = Field(..., ge=0, description="Total bytes: responder → initiator")
    pkt_len_mean: float = Field(..., ge=0, description="Mean packet size in bytes")
    pkt_len_std: float = Field(..., ge=0, description="Std deviation of packet sizes")
    iat_mean: float = Field(..., ge=0, description="Mean inter-arrival time (seconds)")
    iat_std: float = Field(..., ge=0, description="Std deviation of inter-arrival times")
    src_port: int = Field(..., ge=0, le=65535)
    protocol: str = Field(..., description="TCP | UDP | ICMP | OTHER")


class FeatureExtractionResult(BaseModel):
    """Complete feature extraction output with flow context metadata."""
    flow_id: str
    src_ip: str
    dst_ip: str
    external_ip: Optional[str] = Field(None, description="External IP in this flow (if any)")
    is_internal_only: bool = Field(False, description="True if both IPs are private")
    extracted_at: str = Field(..., description="ISO timestamp of extraction")
    features: ExtractedFeatures


class FeatureListResponse(BaseModel):
    """Response for GET /features/latest."""
    items: list[FeatureExtractionResult]
    total: int
