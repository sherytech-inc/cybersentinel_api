import pytest
from unittest.mock import patch, MagicMock
from app.services.capture_platforms.macos import MacOSCaptureAdapter
from app.models.capture_capability import CaptureCapabilityResult, CapturePlatform, CapturePermissionState

def test_macos_remediation_security():
    adapter = MacOSCaptureAdapter()
    result = CaptureCapabilityResult(
        platform=CapturePlatform.macos,
        platform_version="14.0",
        architecture="arm64"
    )

    # We mock the dependency and permission checks to simulate the behavior of the manual check
    with patch.object(adapter, 'inspect_capture_dependency') as mock_dep, \
         patch.object(adapter, 'inspect_permissions') as mock_perm, \
         patch.object(adapter, 'enumerate_interfaces') as mock_enum, \
         patch.object(adapter, 'run_command') as mock_run_command:

        # Simulate that permissions are not granted yet
        def side_effect(r):
            r.permission_state = CapturePermissionState.permissionRequired
        mock_perm.side_effect = side_effect

        success = adapter.execute_remediation(result)

        # Verify it returns false (since manual action is required and perm is not granted)
        assert success is False

        # Verify NO subprocess commands were executed by execute_remediation
        mock_run_command.assert_not_called()

        # Verify read-only functions were called
        mock_dep.assert_called_once()
        mock_perm.assert_called_once()
        mock_enum.assert_called_once()

def test_build_remediation_is_instruction_only():
    adapter = MacOSCaptureAdapter()
    result = CaptureCapabilityResult(
        platform=CapturePlatform.macos,
        platform_version="14.0",
        architecture="arm64"
    )

    adapter.build_remediation(result)
    assert result.remediation_code == "chmodbpf_missing"
    assert "without running the application as an administrator" in result.remediation_message
    assert "osascript" not in result.remediation_message
