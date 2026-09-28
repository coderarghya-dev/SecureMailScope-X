"""
SecureMailScope X - Backend Configuration & Security Settings
"""

import os
from typing import List

# Base Directories
APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.dirname(APP_DIR)
TEMP_UPLOAD_DIR = os.path.join(BACKEND_DIR, "temp_uploads")

# Ensure temporary upload directory exists
os.makedirs(TEMP_UPLOAD_DIR, exist_ok=True)

# Environment & Operational Mode
APP_ENV = os.environ.get("APP_ENV", "development").lower()
REPORT_STORAGE_MODE = os.environ.get("REPORT_STORAGE_MODE", "LOCAL").upper()

# Database Configuration
DATABASE_URL = os.environ.get("DATABASE_URL")

# Security & Upload Constraints
MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

# PCAP Binary Magic Bytes (Standard PCAP and PCAPNG headers)
MAGIC_PCAP_BE = b"\xa1\xb2\xc3\xd4"
MAGIC_PCAP_LE = b"\xd4\xc3\xb2\xa1"
MAGIC_PCAP_NS_BE = b"\xa1\xb2\x3c\x4d"
MAGIC_PCAP_NS_LE = b"\x4d\x3c\xb2\xa1"
MAGIC_PCAPNG = b"\x0a\x0d\x0d\x0a"
VALID_MAGIC_BYTES = (
    MAGIC_PCAP_BE,
    MAGIC_PCAP_LE,
    MAGIC_PCAP_NS_BE,
    MAGIC_PCAP_NS_LE,
    MAGIC_PCAPNG
)

# CORS Configuration
_DEFAULT_CORS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000"
]

_env_cors = os.environ.get("CORS_ORIGINS")
if _env_cors:
    # Comma-separated or whitespace-separated origins
    parsed_origins = [orig.strip() for orig in _env_cors.split(",") if orig.strip()]
    CORS_ORIGINS: List[str] = parsed_origins if parsed_origins else _DEFAULT_CORS
else:
    CORS_ORIGINS: List[str] = _DEFAULT_CORS

# API Metadata
API_TITLE = "SecureMailScope X — Explainable AI Email Forensic API"
API_VERSION = "1.0.0"
API_DESCRIPTION = (
    "Passive network forensic analysis engine for email protocols (SMTP, IMAP, POP3), "
    "STARTTLS/STLS state transitions, TLS 1.3 cryptographic parameters, Capture Health scoring, "
    "Evidence Confidence evaluation, and Post-Quantum readiness assessment."
)
