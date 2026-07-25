"""Single-source executable resolution for packet capture dependencies."""

from dataclasses import dataclass
import os
import shutil
from typing import Optional


@dataclass(frozen=True)
class ResolvedCaptureExecutable:
    name: str
    path: str
    source: str
    checked_locations: tuple[str, ...]


class CaptureExecutableNotFound(RuntimeError):
    pass


def candidate_locations(name: str, configured_path: Optional[str] = None) -> list[str]:
    candidates: list[str] = []
    if configured_path:
        candidates.append(configured_path)
    candidates.extend([
        f"/opt/homebrew/bin/{name}",
        f"/usr/local/bin/{name}",
        f"/Applications/Wireshark.app/Contents/MacOS/{name}",
    ])
    return candidates


def resolve_capture_executable(
    name: str,
    configured_path: Optional[str] = None,
) -> ResolvedCaptureExecutable:
    checked: list[str] = []

    if configured_path:
        checked.append(configured_path)
        if os.path.isfile(configured_path) and os.access(configured_path, os.X_OK):
            return ResolvedCaptureExecutable(
                name=name,
                path=os.path.abspath(configured_path),
                source="configured",
                checked_locations=tuple(checked),
            )

    which_path = shutil.which(name)
    checked.append(f"PATH:{name}")
    if which_path and os.path.isfile(which_path) and os.access(which_path, os.X_OK):
        return ResolvedCaptureExecutable(
            name=name,
            path=os.path.abspath(which_path),
            source="shutil.which",
            checked_locations=tuple(checked),
        )

    for candidate in candidate_locations(name):
        if candidate in checked:
            continue
        checked.append(candidate)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return ResolvedCaptureExecutable(
                name=name,
                path=os.path.abspath(candidate),
                source="deterministic_path",
                checked_locations=tuple(checked),
            )

    raise CaptureExecutableNotFound(
        f"{name} executable was not found. Checked: {', '.join(checked)}"
    )
