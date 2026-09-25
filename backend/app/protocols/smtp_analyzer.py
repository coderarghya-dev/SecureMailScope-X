"""
SecureMailScope X - SMTP Protocol Analyzer

Reconstructs SMTP conversation state machines, banner identification,
and STARTTLS state transitions using packet direction + protocol evidence.
"""

import re
from typing import List, Optional

from ..schemas.forensic import STARTTLSState, PacketEvidence


class SMTPAnalyzer:
    # SMTP service ports
    SMTP_PORTS = {25, 465, 587}

    # Regex patterns
    GREETING_PATTERN = re.compile(
        r"^220[ -](.+)$",
        re.IGNORECASE,
    )

    EHLO_PATTERN = re.compile(
        r"^(?:EHLO|HELO)\s+(.+)$",
        re.IGNORECASE,
    )

    STARTTLS_CMD_PATTERN = re.compile(
        r"^STARTTLS\s*$",
        re.IGNORECASE,
    )

    STARTTLS_RESP_OK_PATTERN = re.compile(
        r"^220[ -].*READY\s+TO\s+START\s+TLS",
        re.IGNORECASE,
    )

    STARTTLS_RESP_FAIL_PATTERN = re.compile(
        r"^(454|501|503)[ -](.+)$",
        re.IGNORECASE,
    )

    @classmethod
    def _get_port(cls, pkt: PacketEvidence, *names) -> Optional[int]:
        """
        Safely obtain a port regardless of the exact PacketEvidence
        field naming convention.
        """
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
        Infer SMTP packet direction from TCP ports.

        Returns:
            "client_to_server"
            "server_to_client"
            None
        """
        src_port = cls._get_port(
            pkt,
            "src_port",
            "tcp_src_port",
            "source_port",
        )

        dst_port = cls._get_port(
            pkt,
            "dst_port",
            "tcp_dst_port",
            "destination_port",
        )

        if src_port in cls.SMTP_PORTS and dst_port not in cls.SMTP_PORTS:
            return "server_to_client"

        if dst_port in cls.SMTP_PORTS and src_port not in cls.SMTP_PORTS:
            return "client_to_server"

        # Fallback when port metadata is unavailable.
        text = (
            getattr(pkt, "summary", None)
            or getattr(pkt, "raw_payload_preview", None)
            or ""
        ).strip()

        if text.upper().startswith("S:"):
            return "server_to_client"

        if text.upper().startswith("C:"):
            return "client_to_server"

        return None

    @classmethod
    def _packet_text(cls, pkt: PacketEvidence) -> str:
        """
        Combine useful textual packet evidence.
        """
        parts = []

        raw_payload = getattr(pkt, "raw_payload_preview", None)
        summary = getattr(pkt, "summary", None)

        if raw_payload:
            parts.append(str(raw_payload))

        if summary and summary not in parts:
            parts.append(str(summary))

        return " | ".join(parts).strip()

    @classmethod
    def analyze_stream_packets(
        cls,
        smtp_packets: List[PacketEvidence],
    ) -> tuple[STARTTLSState, Optional[str], Optional[str]]:

        state = STARTTLSState()

        banner: Optional[str] = None
        helo_name: Optional[str] = None

        # Always process chronologically.
        smtp_packets = sorted(
            smtp_packets,
            key=lambda p: getattr(p, "frame_number", 0),
        )

        for pkt in smtp_packets:
            frame = getattr(pkt, "frame_number", None)
            direction = cls._direction(pkt)

            smtp_req_command = getattr(pkt, "smtp_req_command", None)
            smtp_response_code = getattr(pkt, "smtp_response_code", None)

            text = cls._packet_text(pkt)

            lines = [
                line.strip()
                for line in re.split(r"[\r\n|]+", text)
                if line.strip()
            ]

            # ------------------------------------------------------
            # 1. STRUCTURED SMTP COMMAND FIELD
            # ------------------------------------------------------

            # STARTTLS REQUEST must be CLIENT -> SERVER.
            if (
                direction == "client_to_server"
                and smtp_req_command
                and str(smtp_req_command).strip().upper() == "STARTTLS"
                and not state.requested
            ):
                state.requested = True
                state.requested_frame = frame
                state.requested_command = "STARTTLS"

            # ------------------------------------------------------
            # 2. TEXT / SUMMARY ANALYSIS
            # ------------------------------------------------------

            for line in lines:
                clean = line.strip()

                # Remove Wireshark C:/S: presentation prefix.
                clean_without_prefix = re.sub(
                    r"^[CS]:\s*",
                    "",
                    clean,
                    flags=re.IGNORECASE,
                ).strip()

                upper = clean_without_prefix.upper()

                # --------------------------------------------------
                # SERVER BANNER
                # --------------------------------------------------

                if (
                    direction == "server_to_client"
                    and banner is None
                    and "READY TO START TLS" not in upper
                ):
                    match = cls.GREETING_PATTERN.match(
                        clean_without_prefix
                    )

                    if match:
                        banner = match.group(1).strip()

                # --------------------------------------------------
                # CLIENT EHLO / HELO
                # --------------------------------------------------

                if (
                    direction == "client_to_server"
                    and helo_name is None
                ):
                    match = cls.EHLO_PATTERN.match(
                        clean_without_prefix
                    )

                    if match:
                        helo_name = match.group(1).strip()

                # --------------------------------------------------
                # STARTTLS ADVERTISEMENT
                #
                # Only SERVER -> CLIENT.
                #
                # Do NOT interpret the client's STARTTLS command
                # as server advertisement.
                # --------------------------------------------------

                if (
                    direction == "server_to_client"
                    and not state.advertised
                    and "STARTTLS" in upper
                    and "READY TO START TLS" not in upper
                ):
                    # Typical EHLO capability response:
                    # 250-STARTTLS
                    # 250 STARTTLS
                    # or Wireshark summary containing it.
                    if (
                        upper.startswith("250")
                        or "250-" in upper
                        or "250 " in upper
                        or upper == "STARTTLS"
                    ):
                        state.advertised = True
                        state.advertised_frame = frame
                        state.advertised_text = clean

                # --------------------------------------------------
                # STARTTLS REQUEST
                #
                # Only CLIENT -> SERVER.
                # Must be the actual command, not merely a packet
                # containing the word STARTTLS.
                # --------------------------------------------------

                if (
                    direction == "client_to_server"
                    and not state.requested
                    and cls.STARTTLS_CMD_PATTERN.fullmatch(
                        clean_without_prefix
                    )
                ):
                    state.requested = True
                    state.requested_frame = frame
                    state.requested_command = "STARTTLS"

                # --------------------------------------------------
                # STARTTLS ACCEPTED
                #
                # Only SERVER -> CLIENT and only AFTER request.
                # --------------------------------------------------

                if (
                    direction == "server_to_client"
                    and state.requested
                    and not state.accepted
                    and not state.failed
                    and frame is not None
                    and (
                        state.requested_frame is None
                        or frame > state.requested_frame
                    )
                ):
                    if cls.STARTTLS_RESP_OK_PATTERN.match(
                        clean_without_prefix
                    ):
                        state.accepted = True
                        state.accepted_frame = frame
                        state.accepted_response = clean
                        continue

                    # Fallback for dissector output where the
                    # response code exists separately.
                    if (
                        str(smtp_response_code or "") == "220"
                        and "READY TO START TLS" in upper
                    ):
                        state.accepted = True
                        state.accepted_frame = frame
                        state.accepted_response = clean
                        continue

                    fail_match = cls.STARTTLS_RESP_FAIL_PATTERN.match(
                        clean_without_prefix
                    )

                    if fail_match:
                        state.failed = True
                        state.failure_frame = frame
                        state.failure_reason = (
                            fail_match.group(2).strip()
                        )

        return state, banner, helo_name