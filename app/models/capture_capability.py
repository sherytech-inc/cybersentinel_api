from typing import List, Optional
from enum import Enum
from pydantic import BaseModel, Field
from datetime import datetime

class CapturePlatform(str, Enum):
    macos = "macos"
    windows = "windows"
    linux = "linux"
    unsupported = "unsupported"

class CaptureDependencyState(str, Enum):
    available = "available"
    missing = "missing"
    incompatible = "incompatible"
    inaccessible = "inaccessible"
    unknown = "unknown"

class BinaryVerificationState(str, Enum):
    missing = "missing"
    found = "found"
    inaccessible = "inaccessible"
    incompatible = "incompatible"
    verification_failed = "verification_failed"

class CaptureBinaryInfo(BaseModel):
    found: bool = False
    path: Optional[str] = None
    version: Optional[str] = None
    discovery_source: Optional[str] = None
    executable: bool = False
    verification_state: BinaryVerificationState = BinaryVerificationState.missing

class CapturePermissionState(str, Enum):
    notChecked = "notChecked"
    permissionRequired = "permissionRequired"
    actionRequired = "actionRequired"
    granted = "granted"
    denied = "denied"
    unsupported = "unsupported"
    error = "error"

class CaptureProbeState(str, Enum):
    notRun = "notRun"
    running = "running"
    passed = "passed"
    failed = "failed"
    timedOut = "timedOut"

class CaptureInterface(BaseModel):
    id: str
    system_name: str
    display_name: str
    description: Optional[str] = None
    interface_type: Optional[str] = None
    is_loopback: bool = False
    is_up: bool = False
    addresses: List[str] = Field(default_factory=list)
    recommended: bool = False
    capture_accessible: bool = False

class CaptureCapabilityResult(BaseModel):
    platform: CapturePlatform
    platform_version: str
    architecture: str

    tshark_found: bool = False
    tshark_path: Optional[str] = None
    tshark_version: Optional[str] = None
    tshark_info: Optional[CaptureBinaryInfo] = Field(default_factory=CaptureBinaryInfo)

    dumpcap_found: bool = False
    dumpcap_path: Optional[str] = None
    dumpcap_version: Optional[str] = None
    dumpcap_info: Optional[CaptureBinaryInfo] = Field(default_factory=CaptureBinaryInfo)

    npcap_detected: bool = False
    npcap_version: Optional[str] = None

    chmodbpf_detected: bool = False
    bpf_devices_detected: bool = False

    dumpcap_capabilities: Optional[str] = None

    interfaces: List[CaptureInterface] = Field(default_factory=list)
    recommended_interface: Optional[str] = None

    permission_state: CapturePermissionState = CapturePermissionState.notChecked
    capture_supported: bool = False
    probe_state: CaptureProbeState = CaptureProbeState.notRun

    remediation_code: Optional[str] = None
    remediation_title: Optional[str] = None
    remediation_message: Optional[str] = None
    requires_user_action: bool = False

    last_checked_at: datetime = Field(default_factory=datetime.utcnow)
