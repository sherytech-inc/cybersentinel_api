import os
import shutil
import stat
import json
import uuid
import tempfile
import subprocess
from typing import Optional
from app.services.capture_platforms.base import CapturePlatformAdapter
from app.core.config import get_settings
from app.services.capture_executables import (
    CaptureExecutableNotFound,
    resolve_capture_executable,
)
from app.models.capture_capability import (
    CaptureCapabilityResult,
    CapturePlatform,
    CaptureInterface,
    CapturePermissionState,
    CaptureDependencyState,
    CaptureProbeState,
    CaptureBinaryInfo,
    BinaryVerificationState
)

class MacOSCaptureAdapter(CapturePlatformAdapter):
    def detect_platform(self, result: CaptureCapabilityResult):
        result.platform = CapturePlatform.macos
        # Get OS version
        code, out, _ = self.run_command(["sw_vers", "-productVersion"])
        if code == 0:
            result.platform_version = out.strip()
        code, out, _ = self.run_command(["uname", "-m"])
        if code == 0:
            result.architecture = out.strip()

    def _discover_binary(self, binary_name: str, configured_path: str = "") -> CaptureBinaryInfo:
        info = CaptureBinaryInfo()
        try:
            resolved = resolve_capture_executable(binary_name, configured_path)
        except CaptureExecutableNotFound:
            info.verification_state = BinaryVerificationState.missing
            return info

        discovered_path = resolved.path
        info.found = True
        info.path = discovered_path
        info.discovery_source = resolved.source

        # 3. Check if regular executable file
        if not os.path.isfile(discovered_path):
            info.verification_state = BinaryVerificationState.inaccessible
            return info

        if not os.access(discovered_path, os.X_OK):
            info.verification_state = BinaryVerificationState.inaccessible
            return info

        info.executable = True

        # 4. Probe version
        try:
            result = subprocess.run(
                [discovered_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                shell=False
            )
            if result.returncode == 0:
                info.version = result.stdout.splitlines()[0] if result.stdout else "Unknown"
                info.verification_state = BinaryVerificationState.found
            else:
                info.verification_state = BinaryVerificationState.verification_failed
        except subprocess.TimeoutExpired:
            info.verification_state = BinaryVerificationState.verification_failed
        except Exception:
            info.verification_state = BinaryVerificationState.incompatible

        return info

    def find_tshark(self, result: CaptureCapabilityResult):
        info = self._discover_binary(
            "tshark", get_settings().TSHARK_EXECUTABLE
        )
        result.tshark_info = info
        if info.verification_state == BinaryVerificationState.found:
            result.tshark_found = True
            result.tshark_path = info.path
            result.tshark_version = info.version

    def find_dumpcap(self, result: CaptureCapabilityResult):
        info = self._discover_binary(
            "dumpcap", get_settings().DUMPCAP_EXECUTABLE
        )
        result.dumpcap_info = info
        if info.verification_state == BinaryVerificationState.found:
            result.dumpcap_found = True
            result.dumpcap_path = info.path
            result.dumpcap_version = info.version

    def inspect_capture_dependency(self, result: CaptureCapabilityResult):
        if not result.dumpcap_found:
            return

        # Check if ChmodBPF is installed (launchctl)
        code, out, _ = self.run_command(["launchctl", "list"])
        if code == 0 and "ChmodBPF" in out:
            result.chmodbpf_detected = True

        # Check /dev/bpf existence
        bpf_exists = False
        try:
            for f in os.listdir("/dev"):
                if f.startswith("bpf"):
                    bpf_exists = True
                    break
            result.bpf_devices_detected = bpf_exists
        except Exception:
            pass

    def inspect_permissions(self, result: CaptureCapabilityResult):
        if not result.dumpcap_found:
            result.permission_state = CapturePermissionState.unsupported
            return

        # Test permission by attempting a short dumpcap probe or just checking access to /dev/bpf0
        # Actually, Wireshark installs an access_bpf group.
        # But the best test is if dumpcap can start a capture or if we can read /dev/bpf0
        try:
            # Check if we can read /dev/bpf0
            if os.path.exists("/dev/bpf0"):
                if os.access("/dev/bpf0", os.R_OK):
                    result.permission_state = CapturePermissionState.granted
                else:
                    result.permission_state = CapturePermissionState.permissionRequired
                    result.requires_user_action = True
                    self.build_remediation(result)
            else:
                result.permission_state = CapturePermissionState.error
        except Exception:
            result.permission_state = CapturePermissionState.error

    def enumerate_interfaces(self, result: CaptureCapabilityResult):
        if not result.dumpcap_found:
            return

        # Try JSON output first (newer Wireshark)
        code, out, err = self.run_command([result.dumpcap_path, "-D", "-M"])
        if code == 0 and out.strip().startswith("["):
            try:
                data = json.loads(out)
                interfaces = []
                for item in data:
                    for key, val in item.items():
                        # key is interface name like "en0"
                        is_loop = val.get("loopback", False)
                        addresses = val.get("addrs", [])
                        display = val.get("friendly_name") or key
                        desc = val.get("vendor_description")

                        recommended = False
                        if not is_loop and addresses and ("en" in key or "eth" in key or "wlan" in key):
                            recommended = True

                        interf = CaptureInterface(
                            id=key,
                            system_name=key,
                            display_name=display,
                            description=desc,
                            is_loopback=is_loop,
                            addresses=addresses,
                            recommended=recommended,
                            is_up=True,
                            capture_accessible=(result.permission_state == CapturePermissionState.granted)
                        )
                        interfaces.append(interf)
                result.interfaces = interfaces

                # Pick recommended
                for i in interfaces:
                    if i.recommended:
                        result.recommended_interface = i.id
                        break
                return
            except Exception as e:
                pass

        # Fallback to plain dumpcap -D parsing if JSON didn't work
        code, out, _ = self.run_command([result.dumpcap_path, "-D"])
        if code == 0:
            interfaces = []
            for line in out.splitlines():
                line = line.strip()
                if not line or not line[0].isdigit():
                    continue
                # e.g. "1. en0 (Wi-Fi)"
                parts = line.split(" ", 1)
                if len(parts) < 2:
                    continue
                idx_part = parts[0]
                rest = parts[1]

                name_parts = rest.split(" (", 1)
                system_name = name_parts[0]
                display_name = system_name
                is_loop = False

                if len(name_parts) > 1:
                    desc = name_parts[1].rstrip(")")
                    display_name = desc
                    if "Loopback" in desc:
                        is_loop = True

                interf = CaptureInterface(
                    id=system_name,
                    system_name=system_name,
                    display_name=display_name,
                    is_loopback=is_loop,
                    capture_accessible=(result.permission_state == CapturePermissionState.granted)
                )
                interfaces.append(interf)
            result.interfaces = interfaces

            # Simple recommender
            for i in interfaces:
                if not i.is_loopback and i.system_name.startswith("en"):
                    i.recommended = True
                    result.recommended_interface = i.id
                    break

    def run_bounded_probe(self, result: CaptureCapabilityResult, interface_id: str) -> bool:
        if not result.dumpcap_found:
            result.probe_state = CaptureProbeState.failed
            return False

        result.probe_state = CaptureProbeState.running

        # Temp pcap file
        fd, temp_path = tempfile.mkstemp(suffix=".pcapng")
        os.close(fd)

        try:
            # Capture 2 packets or 3 seconds
            cmd = [
                result.dumpcap_path,
                "-i", interface_id,
                "-c", "2",
                "-a", "duration:3",
                "-w", temp_path
            ]

            code, out, err = self.run_command(cmd, timeout=5)

            # Verify file exists and is larger than 0
            if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
                result.probe_state = CaptureProbeState.passed
                # ensure permission state is recorded as granted
                result.permission_state = CapturePermissionState.granted
                return True
            else:
                result.probe_state = CaptureProbeState.failed
                return False

        except Exception:
            result.probe_state = CaptureProbeState.failed
            return False
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def build_remediation(self, result: CaptureCapabilityResult):
        result.remediation_code = "chmodbpf_missing"
        result.remediation_title = "Packet Capture Permission Required"
        result.remediation_message = "CyberSentinel requires the official Wireshark ChmodBPF helper to capture network traffic without running the application as an administrator."

    def execute_remediation(self, result: CaptureCapabilityResult) -> bool:
        # Remediation is now manual; we just rerun dependency checks
        self.inspect_capture_dependency(result)
        self.inspect_permissions(result)
        self.enumerate_interfaces(result)
        return result.permission_state == CapturePermissionState.granted
