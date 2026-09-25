"""
SecureMailScope X - IMAP Protocol Analyzer
Reconstructs IMAP conversation states, distinguishes Direct TLS from STARTTLS, and parses commands.
"""

import re
from typing import List, Optional, Tuple
from ..schemas.forensic import STARTTLSState, PacketEvidence


class IMAPAnalyzer:
    CAPABILITY_PATTERN = re.compile(r"CAPABILITY\b", re.IGNORECASE)
    STARTTLS_CMD_PATTERN = re.compile(r"^[a-zA-Z0-9]+\s+STARTTLS\b", re.IGNORECASE)
    STARTTLS_OK_PATTERN = re.compile(r"^[a-zA-Z0-9]+\s+OK.*(?:begin tls|ready for tls)", re.IGNORECASE)

    @classmethod
    def analyze_stream_packets(
        cls,
        imap_packets: List[PacketEvidence],
        is_direct_tls: bool = False
    ) -> Tuple[STARTTLSState, Optional[str]]:
        """
        Analyze IMAP packets within a TCP stream.
        """
        state = STARTTLSState()
        banner: Optional[str] = None

        if is_direct_tls:
            # On direct TLS (port 993), no STARTTLS occurs
            return state, None

        for pkt in imap_packets:
            text = (pkt.raw_payload_preview or pkt.summary or "").strip()
            if not text:
                continue

            lines = text.split("\n")
            for line in lines:
                line_clean = line.strip()
                if not line_clean:
                    continue

                # Server greeting
                if not banner and line_clean.startswith("* OK"):
                    banner = line_clean

                # Check STARTTLS capability advertised
                if "STARTTLS" in line_clean.upper() and ("* CAPABILITY" in line_clean.upper() or "CAPABILITY" in line_clean.upper()):
                    state.advertised = True
                    state.advertised_frame = pkt.frame_number
                    state.advertised_text = line_clean

                # Client STARTTLS command
                if cls.STARTTLS_CMD_PATTERN.search(line_clean) or line_clean.upper() == "STARTTLS":
                    state.requested = True
                    state.requested_frame = pkt.frame_number
                    state.requested_command = line_clean

                # Server STARTTLS acceptance
                if state.requested and not state.accepted and not state.failed:
                    if cls.STARTTLS_OK_PATTERN.search(line_clean) or ("OK" in line_clean and "TLS" in line_clean.upper()):
                        state.accepted = True
                        state.accepted_frame = pkt.frame_number
                        state.accepted_response = line_clean

        return state, banner
