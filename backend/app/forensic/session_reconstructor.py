"""
SecureMailScope X - Session Reconstructor
Reconstructs email TCP streams into forensic session models with STARTTLS state machines and TLS parameters.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from ..schemas.forensic import (
    EmailProtocol,
    SecurityMode,
    EmailSession,
    PacketEvidence,
    STARTTLSState,
    TLSVersion
)
from ..protocols.smtp_analyzer import SMTPAnalyzer
from ..protocols.imap_analyzer import IMAPAnalyzer
from ..protocols.pop3_analyzer import POP3Analyzer
from ..tls.tls_dissector import TLSDissector
from .pcap_reader import SMTP_PORTS, IMAP_PORTS, POP3_PORTS
from .health_scorer import HealthScorer
from .confidence_scorer import ConfidenceScorer
from .rule_engine import CryptographicRuleEngine


class SessionReconstructor:
    @classmethod
    def reconstruct_sessions(cls, raw_packets: List[Dict[str, Any]]) -> List[EmailSession]:
        """Group raw packets into email sessions and analyze cryptographic transitions."""
        streams: Dict[int, List[Dict[str, Any]]] = defaultdict(list)

        for pkt in raw_packets:
            stream_id = pkt["stream_id"]
            if stream_id >= 0:
                streams[stream_id].append(pkt)

        email_sessions: List[EmailSession] = []

        for stream_id, pkts in streams.items():
            session = cls._analyze_stream(stream_id, pkts)
            if session:
                email_sessions.append(session)

        # Sort sessions chronologically
        email_sessions.sort(key=lambda s: s.start_time_epoch)
        return email_sessions

    @classmethod
    def _analyze_stream(cls, stream_id: int, pkts: List[Dict[str, Any]]) -> Optional[EmailSession]:
        if not pkts:
            return None

        # Sort packets within stream by frame number
        pkts.sort(key=lambda p: p["frame_number"])

        first_pkt = pkts[0]
        last_pkt = pkts[-1]

        # Determine Server vs Client
        # Identify by well-known server port first
        p1_src, p1_dst = first_pkt["src_port"], first_pkt["dst_port"]
        all_email_ports = SMTP_PORTS | IMAP_PORTS | POP3_PORTS

        if p1_dst in all_email_ports:
            client_ip, client_port = first_pkt["src_ip"], p1_src
            server_ip, server_port = first_pkt["dst_ip"], p1_dst
        elif p1_src in all_email_ports:
            server_ip, server_port = first_pkt["src_ip"], p1_src
            client_ip, client_port = first_pkt["dst_ip"], p1_dst
        else:
            # Fallback: check if any packet has an email protocol string
            is_email = any(p["protocol"] in ["SMTP", "IMAP", "POP"] for p in pkts)
            if not is_email:
                return None
            client_ip, client_port = first_pkt["src_ip"], p1_src
            server_ip, server_port = first_pkt["dst_ip"], p1_dst

        # Determine Protocol
        protocol = EmailProtocol.UNKNOWN
        if server_port in SMTP_PORTS or any("SMTP" in p["protocol"] for p in pkts):
            protocol = EmailProtocol.SMTP
        elif server_port in IMAP_PORTS or any("IMAP" in p["protocol"] for p in pkts):
            protocol = EmailProtocol.IMAP
        elif server_port in POP3_PORTS or any("POP" in p["protocol"] for p in pkts):
            protocol = EmailProtocol.POP3
        else:
            return None

        # Direct TLS indicator (ports 465, 993, 995 are implicitly direct TLS)
        is_direct_tls_port = server_port in {465, 993, 995}

        # Build packet evidence list
        evidence_packets: List[PacketEvidence] = []
        syn_observed = False
        fin_rst_observed = False

        for p in pkts:
            if p.get("is_syn"):
                syn_observed = True
            if p.get("is_fin") or p.get("is_rst"):
                fin_rst_observed = True

            iso_time = datetime.fromtimestamp(p["timestamp_epoch"], tz=timezone.utc).isoformat()
            evidence_packets.append(PacketEvidence(
                frame_number=p["frame_number"],
                timestamp_epoch=p["timestamp_epoch"],
                timestamp_iso=iso_time,
                src_ip=p["src_ip"],
                src_port=p["src_port"],
                dst_ip=p["dst_ip"],
                dst_port=p["dst_port"],
                protocol=p["protocol"],
                length=0,
                summary=p["info"],
                raw_payload_preview=p["info"],
                smtp_req_command=p.get("smtp_req_command"),
                smtp_response_code=p.get("smtp_response_code"),
                smtp_response_parameter=p.get("smtp_response_parameter")
            ))

        start_time = first_pkt["timestamp_epoch"]
        end_time = last_pkt["timestamp_epoch"]
        duration = max(0.0, end_time - start_time)

        # STARTTLS Analysis
        starttls_state = STARTTLSState()
        banner: Optional[str] = None
        helo_name: Optional[str] = None
        server_hostname: Optional[str] = None

        if protocol == EmailProtocol.SMTP and not is_direct_tls_port:
            smtp_pkts = [
                ep for ep in evidence_packets
                if "SMTP" in ep.protocol or ep.smtp_req_command or ep.smtp_response_code or "SMTP" in ep.summary or "220" in ep.summary or "STARTTLS" in ep.summary
            ]
            starttls_state, banner, helo_name = SMTPAnalyzer.analyze_stream_packets(smtp_pkts)
            if banner:
                # Extract server hostname from banner (e.g., "220 smtp.gmail.com ESMTP ...")
                banner_parts = banner.split()
                if len(banner_parts) > 0:
                    server_hostname = banner_parts[0]
        elif protocol == EmailProtocol.IMAP:
            imap_pkts = [ep for ep in evidence_packets if "IMAP" in ep.protocol]
            starttls_state, banner = IMAPAnalyzer.analyze_stream_packets(imap_pkts, is_direct_tls=is_direct_tls_port)
        elif protocol == EmailProtocol.POP3:
            pop3_pkts = [ep for ep in evidence_packets if "POP" in ep.protocol.upper() or ep.summary or ep.raw_payload_preview]
            starttls_state, banner = POP3Analyzer.analyze_stream_packets(pop3_pkts, is_direct_tls=is_direct_tls_port)

        # TLS Handshake Search within stream
        client_hello_frame: Optional[int] = None
        client_hello_time: Optional[float] = None
        server_hello_frame: Optional[int] = None
        server_hello_time: Optional[float] = None
        sni: Optional[str] = None
        raw_version: Optional[str] = None
        supported_ver_ext: Optional[str] = None
        selected_cipher: Optional[str] = None

        for p in pkts:
            info = p["info"]
            handshake_type = p.get("tls_handshake_type") or ""

            # Check Client Hello (handshake type 1)
            if "Client Hello" in info or handshake_type == "1" or "1" in handshake_type.split(","):
                if not client_hello_frame:
                    client_hello_frame = p["frame_number"]
                    client_hello_time = p["timestamp_epoch"]
                    if p.get("tls_sni"):
                        sni = p["tls_sni"]
                    elif "SNI=" in info:
                        # Extract SNI from info string e.g. (SNI=smtp.gmail.com)
                        try:
                            sni = info.split("SNI=")[1].split(")")[0].strip()
                        except IndexError:
                            pass

            # Check Server Hello (handshake type 2)
            if "Server Hello" in info or handshake_type == "2" or "2" in handshake_type.split(","):
                if not server_hello_frame:
                    server_hello_frame = p["frame_number"]
                    server_hello_time = p["timestamp_epoch"]
                    raw_version = p.get("tls_handshake_version") or p.get("tls_record_version")
                    # TShark info column often says "TLSv1.3 Server Hello" or "TLSv1.2 Server Hello"
                    if "TLSv1.3" in info or "TLS 1.3" in p.get("protocol", ""):
                        supported_ver_ext = "0x0304"
                    elif "TLSv1.2" in info:
                        supported_ver_ext = "0x0303"

                    if p.get("tls_ciphersuite"):
                        selected_cipher = p["tls_ciphersuite"]
                    else:
                        # Default TLS 1.3 standard cipher if not individually exposed in fields
                        if supported_ver_ext == "0x0304":
                            selected_cipher = "0x1301"

        key_share_observed = False
        server_kx_observed = False
        for p in pkts:
            ext_types = [t.strip() for t in str(p.get("tls_extension_types") or "").split(",") if t.strip()]
            if "51" in ext_types or "0x0033" in ext_types or "0x33" in ext_types:
                key_share_observed = True
            handshake_types = [h.strip() for h in str(p.get("tls_handshake_type") or "").split(",") if h.strip()]
            if "12" in handshake_types:
                server_kx_observed = True

        tls_details = None
        if client_hello_frame or server_hello_frame:
            tls_details = TLSDissector.dissect_handshake(
                client_hello_frame=client_hello_frame,
                client_hello_time=client_hello_time,
                server_hello_frame=server_hello_frame,
                server_hello_time=server_hello_time,
                sni=sni or server_hostname,
                alpn=None,
                raw_version=raw_version,
                supported_version_ext=supported_ver_ext,
                cipher_code=selected_cipher,
                key_share_observed=key_share_observed,
                server_kx_observed=server_kx_observed
            )

        # Determine Security Mode and Upgrade Success
        if is_direct_tls_port:
            security_mode = SecurityMode.DIRECT_TLS
        elif starttls_state.accepted:
            if client_hello_frame and server_hello_frame:
                starttls_state.upgrade_successful = True
                security_mode = SecurityMode.STARTTLS_ACCEPTED
            else:
                security_mode = SecurityMode.STARTTLS_ACCEPTED
        elif starttls_state.requested:
            security_mode = SecurityMode.STARTTLS_REQUESTED
        elif starttls_state.advertised:
            security_mode = SecurityMode.STARTTLS_ADVERTISED
        elif client_hello_frame and not is_direct_tls_port:
            # TLS started directly on submission or non-standard port
            security_mode = SecurityMode.DIRECT_TLS
        else:
            security_mode = SecurityMode.PLAINTEXT

        session_id = f"stream_{stream_id}_{client_ip}_{client_port}_{server_ip}_{server_port}"

        # Phase 3 Scoring and Assessment
        capture_health = HealthScorer.calculate_health(
            raw_packets=pkts,
            syn_observed=syn_observed,
            fin_rst_observed=fin_rst_observed,
            duration_seconds=duration
        )

        evidence_confidence = ConfidenceScorer.calculate_confidence(
            tls_details=tls_details,
            security_mode=security_mode
        )

        session = EmailSession(
            session_id=session_id,
            stream_index=stream_id,
            protocol=protocol,
            security_mode=security_mode,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            server_hostname=sni or server_hostname,
            start_time_epoch=start_time,
            end_time_epoch=end_time,
            duration_seconds=duration,
            total_packets=len(pkts),
            total_bytes=0,
            greeting_banner=banner,
            client_helo_name=helo_name,
            starttls_state=starttls_state,
            tls_details=tls_details,
            evidence_packets=evidence_packets,
            syn_observed=syn_observed,
            fin_rst_observed=fin_rst_observed,
            is_stream_complete=syn_observed and fin_rst_observed,
            capture_health=capture_health,
            evidence_confidence=evidence_confidence
        )

        session.security_assessment = CryptographicRuleEngine.evaluate_session(session)
        return session
