"""
SecureMailScope X - TShark Detector
Discovers and validates local TShark executable installations.
"""

import os
import shutil
import subprocess
from typing import Optional, Tuple


DEFAULT_TSHARK_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    r"D:\Program Files\Wireshark\tshark.exe",
]


class TSharkDetector:
    _cached_path: Optional[str] = None
    _cached_version: Optional[str] = None

    @classmethod
    def find_tshark(cls) -> Optional[str]:
        """Locate TShark binary on the host system."""
        if cls._cached_path and os.path.isfile(cls._cached_path):
            return cls._cached_path

        # 1. Check system PATH
        path_in_env = shutil.which("tshark")
        if path_in_env and os.path.isfile(path_in_env):
            cls._cached_path = path_in_env
            return path_in_env

        # 2. Check standard Windows installation paths
        for path in DEFAULT_TSHARK_PATHS:
            if os.path.isfile(path):
                cls._cached_path = path
                return path

        return None

    @classmethod
    def get_version(cls) -> Tuple[bool, str]:
        """Return (is_available, version_string_or_error)."""
        tshark_bin = cls.find_tshark()
        if not tshark_bin:
            return False, "TShark executable not found in PATH or standard installation directories."

        if cls._cached_version:
            return True, cls._cached_version

        try:
            result = subprocess.run(
                [tshark_bin, "-v"],
                capture_output=True,
                text=True,
                timeout=5,
                check=True
            )
            first_line = result.stdout.splitlines()[0] if result.stdout else "TShark (version unknown)"
            cls._cached_version = first_line
            return True, first_line
        except Exception as e:
            return False, f"Failed to execute TShark at {tshark_bin}: {str(e)}"
