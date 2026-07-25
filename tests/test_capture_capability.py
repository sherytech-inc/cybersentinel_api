import pytest
from app.models.capture_capability import CaptureCapabilityResult, CapturePlatform, CapturePermissionState
from app.services.capture_capability_service import CaptureCapabilityService
from app.services.capture_platforms.macos import MacOSCaptureAdapter

class FakeMacOSAdapter(MacOSCaptureAdapter):
    def __init__(self, tshark_found=True, dumpcap_found=True, permission=CapturePermissionState.granted):
        self._tshark_found = tshark_found
        self._dumpcap_found = dumpcap_found
        self._permission = permission

    def find_tshark(self, result):
        if self._tshark_found:
            result.tshark_found = True
            result.tshark_path = "/fake/tshark"

    def find_dumpcap(self, result):
        if self._dumpcap_found:
            result.dumpcap_found = True
            result.dumpcap_path = "/fake/dumpcap"

    def inspect_permissions(self, result):
        result.permission_state = self._permission

    def enumerate_interfaces(self, result):
        from app.models.capture_capability import CaptureInterface
        result.interfaces = [
            CaptureInterface(id="en0", system_name="en0", display_name="Wi-Fi", is_loopback=False, recommended=True)
        ]
        result.recommended_interface = "en0"

    def run_bounded_probe(self, result, interface_id):
        if self._dumpcap_found and self._permission == CapturePermissionState.granted:
            result.probe_state = "passed"
            return True
        return False

def test_capabilities_success():
    service = CaptureCapabilityService()
    service._adapter = FakeMacOSAdapter()

    res = service.refresh_capabilities()
    assert res.tshark_found is True
    assert res.dumpcap_found is True
    assert res.permission_state == CapturePermissionState.granted
    assert res.capture_supported is True
    assert len(res.interfaces) == 1
    assert res.interfaces[0].id == "en0"

def test_capabilities_missing_dumpcap():
    service = CaptureCapabilityService()
    service._adapter = FakeMacOSAdapter(dumpcap_found=False)

    res = service.refresh_capabilities()
    assert res.dumpcap_found is False
    assert res.capture_supported is False

def test_capabilities_permission_required():
    service = CaptureCapabilityService()
    service._adapter = FakeMacOSAdapter(permission=CapturePermissionState.permissionRequired)

    res = service.refresh_capabilities()
    assert res.permission_state == CapturePermissionState.permissionRequired
    assert res.capture_supported is False

def test_probe_success():
    service = CaptureCapabilityService()
    service._adapter = FakeMacOSAdapter()

    res = service.run_probe("en0")
    assert res.probe_state == "passed"

def test_probe_invalid_interface():
    service = CaptureCapabilityService()
    service._adapter = FakeMacOSAdapter()

    res = service.run_probe("invalid_iface")
    assert res.remediation_code == "invalid_interface"
