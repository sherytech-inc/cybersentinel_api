import subprocess
from typing import Optional, List, Tuple
from abc import ABC, abstractmethod
from app.models.capture_capability import CaptureCapabilityResult, CaptureInterface

class CapturePlatformAdapter(ABC):
    @abstractmethod
    def detect_platform(self, result: CaptureCapabilityResult):
        pass

    @abstractmethod
    def find_tshark(self, result: CaptureCapabilityResult):
        pass

    @abstractmethod
    def find_dumpcap(self, result: CaptureCapabilityResult):
        pass

    @abstractmethod
    def inspect_capture_dependency(self, result: CaptureCapabilityResult):
        pass

    @abstractmethod
    def inspect_permissions(self, result: CaptureCapabilityResult):
        pass

    @abstractmethod
    def enumerate_interfaces(self, result: CaptureCapabilityResult):
        pass

    @abstractmethod
    def run_bounded_probe(self, result: CaptureCapabilityResult, interface_id: str) -> bool:
        pass

    @abstractmethod
    def build_remediation(self, result: CaptureCapabilityResult):
        pass

    @abstractmethod
    def execute_remediation(self, result: CaptureCapabilityResult) -> bool:
        pass

    def run_command(self, cmd: List[str], timeout: int = 5) -> Tuple[int, str, str]:
        """Safely executes a shell command returning exit code, stdout, stderr."""
        try:
            # We never use shell=True and pass absolute arguments
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return process.returncode, process.stdout, process.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Timeout expired"
        except FileNotFoundError as e:
            return -2, "", str(e)
        except Exception as e:
            return -3, "", str(e)
