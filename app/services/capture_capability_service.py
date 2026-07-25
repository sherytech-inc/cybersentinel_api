import sys
from datetime import datetime
from app.models.capture_capability import CaptureCapabilityResult, CapturePlatform, CapturePermissionState
from app.services.capture_platforms.base import CapturePlatformAdapter
from app.services.capture_platforms.macos import MacOSCaptureAdapter
from app.services.capture_platforms.windows import WindowsCaptureAdapter
from app.services.capture_platforms.linux import LinuxCaptureAdapter

class CaptureCapabilityService:
    def __init__(self):
        self._cached_result = None
        self._adapter = self._get_platform_adapter()

    def _get_platform_adapter(self) -> CapturePlatformAdapter:
        platform = sys.platform
        if platform == "darwin":
            return MacOSCaptureAdapter()
        elif platform == "win32":
            return WindowsCaptureAdapter()
        elif platform.startswith("linux"):
            return LinuxCaptureAdapter()
        else:
            return None

    def refresh_capabilities(self) -> CaptureCapabilityResult:
        result = CaptureCapabilityResult(
            platform=CapturePlatform.unsupported,
            platform_version="unknown",
            architecture="unknown"
        )

        if not self._adapter:
            self._cached_result = result
            return result

        self._adapter.detect_platform(result)
        self._adapter.find_tshark(result)
        self._adapter.find_dumpcap(result)
        self._adapter.inspect_capture_dependency(result)
        self._adapter.inspect_permissions(result)
        self._adapter.enumerate_interfaces(result)

        if result.tshark_found and result.dumpcap_found and result.permission_state == CapturePermissionState.granted:
            result.capture_supported = True

        result.last_checked_at = datetime.utcnow()
        self._cached_result = result
        return result

    def get_capabilities(self) -> CaptureCapabilityResult:
        if not self._cached_result:
            return self.refresh_capabilities()
        return self._cached_result

    def run_probe(self, interface_id: str) -> CaptureCapabilityResult:
        result = self.get_capabilities()
        if not self._adapter:
            return result

        valid = False
        for iface in result.interfaces:
            if iface.id == interface_id:
                valid = True
                break

        if not valid:
            result.remediation_code = "invalid_interface"
            return result

        self._adapter.run_bounded_probe(result, interface_id)

        if result.tshark_found and result.dumpcap_found and result.permission_state == CapturePermissionState.granted:
            result.capture_supported = True
            result.remediation_code = "capture_ready"

        result.last_checked_at = datetime.utcnow()
        self._cached_result = result
        return result

    def execute_remediation(self) -> bool:
        if not self._adapter:
            return False
        result = self.get_capabilities()
        success = self._adapter.execute_remediation(result)
        if success:
            self.refresh_capabilities()
        return success
