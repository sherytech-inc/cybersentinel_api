import os
from unittest.mock import patch

import pytest

from app.services.capture_executables import (
    CaptureExecutableNotFound,
    resolve_capture_executable,
)


def test_configured_executable_has_priority(tmp_path):
    executable = tmp_path / "tshark"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)

    with patch("shutil.which", return_value="/other/tshark"):
        resolved = resolve_capture_executable("tshark", str(executable))

    assert resolved.path == str(executable)
    assert resolved.source == "configured"


def test_homebrew_fallback_is_used_when_path_lookup_fails():
    with patch("shutil.which", return_value=None), patch(
        "os.path.isfile", side_effect=lambda path: path == "/opt/homebrew/bin/tshark"
    ), patch("os.access", return_value=True):
        resolved = resolve_capture_executable("tshark")

    assert resolved.path == "/opt/homebrew/bin/tshark"


def test_missing_executable_reports_checked_locations_safely():
    with patch("shutil.which", return_value=None), patch(
        "os.path.isfile", return_value=False
    ):
        with pytest.raises(CaptureExecutableNotFound) as exc:
            resolve_capture_executable("tshark")

    message = str(exc.value)
    assert "/opt/homebrew/bin/tshark" in message
    assert "/usr/local/bin/tshark" in message
    assert "/Applications/Wireshark.app/Contents/MacOS/tshark" in message
