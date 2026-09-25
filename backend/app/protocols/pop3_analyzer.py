"""
SecureMailScope X - POP3 / POP3S Protocol Analyzer
Reconstructs POP3 conversation states, parses CAPA / STLS transitions using packet direction + protocol evidence,
and distinguishes Direct TLS from STLS.
"""

import re
from typing import List, Optional, Tuple
from ..schemas.forensic import STARTTLSState, PacketEvidence


class POP3Analyzer:
    POP3_PORTS = {110, 995}

    CAPA_CMD_PATTERN = re.compile(r"^(?:Command:\s*|Request:\s*)?CAPA\b", re.IGNORECASE)
    STLS_CMD_PATTERN = re.compile(r"^(?:Command:\s*|Request:\s*)?STLS\s*$", re.IGNORECASE)
    STLS_OK_PATTERN = re.compile(r"^\+OK.*(?:begin tls|ready for tls|tls negotiation|start tls)", re.IGNORECASE)
    POP3_ERR_PATTERN = re.compile(r"^-ERR\s*(.*)$", re.IGNORECASE)

    @classmethod
    def _get_port(cls, pkt: PacketEvidence, *names) -> Optional[int]:
        """Safely obtain a port number from packet metadata."""
        for name in names:
            value = getattr(pkt, name, None)
            if value is None:
                continue
            try:
                return int(value)
            except (TypeError, ValueError):
                pass
        return None

    @classmethod
    def _direction(cls, pkt: PacketEvidence) -> Optional[str]:
        """
        Infer POP3 packet flow direction from TCP ports and presentation metadata.
        Returns: 'client_to_server', 'server_to_client', or None.
        """
        src_port = cls._get_port(pkt, "src_port", "tcp_src_port", "source_port")
        dst_port = cls._get_port(pkt, "dst_port", "tcp_dst_port", "destination_port")

        if src_port in cls.POP3_PORTS and dst_port not in cls.POP3_PORTS:
            return "server_to_client"
        if dst_port in cls.POP3_PORTS and src_port not in cls.POP3_PORTS:
            return "client_to_server"

        # Fallback inspection on presentation prefixes and keywords
        summary = (getattr(pkt, "summary", "") or "").strip()
        raw = (getattr(pkt, "raw_payload_preview", "") or "").strip()

        for candidate in [summary, raw]:
            c_clean = candidate.strip()
            c_upper = c_clean.upper()
            if not c_clean:
                continue
            if (
                c_upper.startswith("S:")
                or c_upper.startswith("RESPONSE:")
                or c_clean.startswith("+OK")
                or c_clean.startswith("-ERR")
            ):
                return "server_to_client"
            if (
                c_upper.startswith("C:")
                or c_upper.startswith("COMMAND:")
                or c_upper.startswith("REQUEST:")
                or cls.STLS_CMD_PATTERN.match(c_clean)
                or cls.CAPA_CMD_PATTERN.match(c_clean)
                or c_upper == "STLS"
                or c_upper == "CAPA"
            ):
                return "client_to_server"

        return None

    @classmethod
    def analyze_stream_packets(
        cls,
        pop3_packets: List[PacketEvidence],
        is_direct_tls: bool = False
    ) -> Tuple[STARTTLSState, Optional[str]]:
        """
        Analyze POP3 packets within a TCP stream using directional packet evidence.
        """
        state = STARTTLSState()
        banner: Optional[str] = None

        if is_direct_tls:
            # On direct TLS (port 995), no STLS handshake occurs
            return state, None

        # Sort chronologically by frame number
        sorted_pkts = sorted(pop3_packets, key=lambda p: getattr(p, "frame_number", 0))

        for pkt in sorted_pkts:
            frame = getattr(pkt, "frame_number", None)
            direction = cls._direction(pkt)

            text = (pkt.raw_payload_preview or pkt.summary or "").strip()
            if not text:
                continue

            lines = text.split("\n")
            for line in lines:
                line_clean = line.strip()
                if not line_clean:
                    continue

                # Strip potential presentation prefixes e.g. "S: " or "C: " or "Response: "
                clean_no_prefix = re.sub(
                    r"^(?:[CS]:|Response:|Command:|Request:)\s*",
                    "",
                    line_clean,
                    flags=re.IGNORECASE
                ).strip()
                upper = clean_no_prefix.upper()

                # --------------------------------------------------
                # 1. SERVER BANNER & CAPABILITY ADVERTISEMENT (Server -> Client)
                # --------------------------------------------------
                if direction == "server_to_client":
                    # Server greeting (first +OK line before client STLS request)
                    if not banner and clean_no_prefix.startswith("+OK") and not state.requested:
                        banner = clean_no_prefix

                    # STLS capability advertisement in CAPA response
                    if "STLS" in upper and not state.advertised and not state.requested:
                        tokens = [t.strip() for t in re.split(r"[\s,]+", upper) if t.strip()]
                        if "STLS" in tokens or upper == "STLS" or "CAPABILITY" in upper or "CAPA" in upper:
                            state.advertised = True
                            state.advertised_frame = frame
                            state.advertised_text = clean_no_prefix

                    # Server STLS response (acceptance or failure) after request
                    if state.requested and not state.accepted and not state.failed:
                        if frame is not None and (state.requested_frame is None or frame >= state.requested_frame):
                            if clean_no_prefix.startswith("+OK"):
                                state.accepted = True
                                state.accepted_frame = frame
                                state.accepted_response = clean_no_prefix
                            elif clean_no_prefix.startswith("-ERR"):
                                match = cls.POP3_ERR_PATTERN.match(clean_no_prefix)
                                state.failed = True
                                state.failure_frame = frame
                                state.failure_reason = match.group(1).strip() if match else clean_no_prefix

                # --------------------------------------------------
                # 2. CLIENT STLS COMMAND REQUEST (Client -> Server)
                # --------------------------------------------------
                elif direction == "client_to_server":
                    if not state.requested:
                        if cls.STLS_CMD_PATTERN.match(clean_no_prefix) or clean_no_prefix.upper() == "STLS":
                            state.requested = True
                            state.requested_frame = frame
                            state.requested_command = "STLS"

                # --------------------------------------------------
                # 3. AMBIGUOUS DIRECTION (Neither port nor prefix determined)
                # Do NOT execute both client and server logic simultaneously
                # --------------------------------------------------
                else:
                    # If response marker is present, treat strictly as server response
                    if clean_no_prefix.startswith("+OK") or clean_no_prefix.startswith("-ERR"):
                        if not banner and clean_no_prefix.startswith("+OK") and not state.requested:
                            banner = clean_no_prefix
                        if state.requested and not state.accepted and not state.failed:
                            if clean_no_prefix.startswith("+OK"):
                                state.accepted = True
                                state.accepted_frame = frame
                                state.accepted_response = clean_no_prefix
                            elif clean_no_prefix.startswith("-ERR"):
                                match = cls.POP3_ERR_PATTERN.match(clean_no_prefix)
                                state.failed = True
                                state.failure_frame = frame
                                state.failure_reason = match.group(1).strip() if match else clean_no_prefix

        return state, banner
