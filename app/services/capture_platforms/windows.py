from app.services.capture_platforms.base import CapturePlatformAdapter
from app.models.capture_capability import CaptureCapabilityResult, CapturePlatform, CapturePermissionState

class WindowsCaptureAdapter(CapturePlatformAdapter):
    def detect_platform(self, result: CaptureCapabilityResult):
        result.platform = CapturePlatform.windows

    def find_tshark(self, result: CaptureCapabilityResult):
        pass

    def find_dumpcap(self, result: CaptureCapabilityResult):
        pass

    def inspect_capture_dependency(self, result: CaptureCapabilityResult):
        pass

    def inspect_permissions(self, result: CaptureCapabilityResult):
        result.permission_state = CapturePermissionState.unsupported

    def enumerate_interfaces(self, result: CaptureCapabilityResult):
        pass

    def run_bounded_probe(self, result: CaptureCapabilityResult, interface_id: str) -> bool:
        return False

    def build_remediation(self, result: CaptureCapabilityResult):
        result.remediation_code = "unsupported_platform"

    def execute_remediation(self, result: CaptureCapabilityResult) -> bool:
        return False
