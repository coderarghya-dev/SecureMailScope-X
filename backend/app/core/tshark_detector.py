"""
SecureMailScope X - TShark Detector
Discovers and validates local TShark executable installations.
"""

import os
import shutil
import subprocess
from typing import Optional, Tuple


DEFAULT_TSHARK_PATHS = [
    "/usr/bin/tshark",
    "/usr/local/bin/tshark",
    "/usr/sbin/tshark",
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    r"D:\Program Files\Wireshark\tshark.exe",
]


class TSharkDetector:
    _cached_path: Optional[str] = None
    _cached_version: Optional[str] = None
    _is_available: Optional[bool] = None
    _detection_message: Optional[str] = None

    @classmethod
    def find_tshark(cls) -> Optional[str]:
        """Locate TShark binary on the host system with memoization."""
        if cls._cached_path is not None:
            return cls._cached_path if cls._cached_path else None

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

        cls._cached_path = ""
        return None

    @classmethod
    def get_version(cls) -> Tuple[bool, str]:
        """Return (is_available, version_string_or_error) with memory caching."""
        if cls._is_available is not None and cls._detection_message is not None:
            return cls._is_available, cls._detection_message

        tshark_bin = cls.find_tshark()
        if not tshark_bin:
            cls._is_available = False
            cls._detection_message = "TShark executable not found in PATH or standard installation directories."
            return False, cls._detection_message

        try:
            result = subprocess.run(
                [tshark_bin, "-v"],
                capture_output=True,
                text=True,
                timeout=3,
                check=True
            )
            first_line = result.stdout.splitlines()[0] if result.stdout else "TShark (version unknown)"
            cls._is_available = True
            cls._detection_message = first_line
            cls._cached_version = first_line
            return True, first_line
        except Exception as e:
            cls._is_available = False
            cls._detection_message = f"Failed to execute TShark at {tshark_bin}: {str(e)}"
            return False, cls._detection_message
