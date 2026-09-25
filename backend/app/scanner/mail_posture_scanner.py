"""
SecureMailScope X - Active Mail Server Posture Scanner (Phase 9 & 9.5)
Executes safe, strictly opt-in active network probes against email services on ports:
- SMTP: 25, 465, 587
- IMAP: 143, 993
- POP3: 110, 995

CORE SAFETY / FORENSIC BOUNDARIES:
1. Active probe data is labeled source="ACTIVE_NETWORK_PROBE", historical_applicability="CURRENT_STATE_ONLY".
2. Scanner is strictly opt-in; passive PCAP inspection never connects to network.
3. Strict port allowlist {25, 465, 587, 110, 143, 993, 995}.
4. No credential authentication (AUTH, LOGIN, PLAIN, XOAUTH, USER, PASS, SELECT prohibited).
5. No mail sending (MAIL FROM, RCPT TO, DATA prohibited).
6. Scan failures map to TIMEOUT, CONNECTION_FAILED, RESOLUTION_FAILED, TLS_VERIFICATION_FAILED (never INSECURE).
7. Default SSRF defense blocks loopback, private RFC1918, link-local, multicast, unspecified IPs.
8. DNS Pinning: Connects directly to pre-validated IP to prevent DNS rebinding; preserves SNI for hostname.
9. Bounded timeouts (<= 5.0s) and bounded reads (<= 4096 bytes).
"""

import socket
import ssl
import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa

from app.scanner.target_validator import TargetValidator, ALLOWED_MAIL_PORTS, PORT_PROTOCOL_MAP

MAX_RESPONSE_BYTES = 4096
DEFAULT_TIMEOUT_SEC = 5.0
SAFE_CLIENT_ID = "securemailscope.probe"


@dataclass
class CertificateDetails:
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    public_key_algorithm: str = ""
    public_key_bits: Optional[int] = None
    signature_algorithm: str = ""
    sha256_fingerprint: str = ""
    trust_validation_mode: str = "NOT_VALIDATED"  # NOT_VALIDATED, CA_CHAIN_ONLY, CA_AND_HOSTNAME
    ca_chain_validated: Optional[bool] = None
    hostname_validated: Optional[bool] = None
    trust_status: str = "NOT_VALIDATED"  # NOT_VALIDATED, VALIDATED, TRUST_FAILED, HOSTNAME_MISMATCH
    is_expired: bool = False
    validity_reference_time: str = ""
    reference_time_source: str = "ACTIVE_PROBE_TIME"
    self_issued: bool = False
    san_list: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "public_key_algorithm": self.public_key_algorithm,
            "public_key_bits": self.public_key_bits,
            "signature_algorithm": self.signature_algorithm,
            "sha256_fingerprint": self.sha256_fingerprint,
            "trust_validation_mode": self.trust_validation_mode,
            "ca_chain_validated": self.ca_chain_validated,
            "hostname_validated": self.hostname_validated,
            "trust_status": self.trust_status,
            "is_expired": self.is_expired,
            "validity_reference_time": self.validity_reference_time,
            "reference_time_source": self.reference_time_source,
            "self_issued": self.self_issued,
            "san_list": self.san_list,
        }


@dataclass
class TLSPostureDetails:
    negotiated_version: Optional[str] = None
    selected_cipher: Optional[str] = None
    cipher_posture: str = "STANDARD"  # STANDARD, WEAK, UNKNOWN_POSTURE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "negotiated_version": self.negotiated_version,
            "selected_cipher": self.selected_cipher,
            "cipher_posture": self.cipher_posture,
        }


@dataclass
class PortProbeResult:
    port: int
    protocol: str
    mode: str
    connection_status: str  # SUCCESS, CONNECTION_FAILED, TIMEOUT, RESOLUTION_FAILED, TLS_VERIFICATION_FAILED
    probe_started_at: str
    probe_completed_at: str
    requested_hostname: str = ""
    connected_ip: Optional[str] = None
    latency_ms: float = 0.0
    banner: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    starttls_status: str = "NOT_APPLICABLE"  # STARTTLS_NOT_ADVERTISED, STARTTLS_ADVERTISED, STARTTLS_ACCEPTED, STARTTLS_REJECTED, PROBE_INCOMPLETE, NOT_APPLICABLE
    starttls_advertised: bool = False
    starttls_attempted: bool = False
    starttls_accepted: bool = False
    response_truncated: bool = False
    tls: Optional[TLSPostureDetails] = None
    certificate: Optional[CertificateDetails] = None
    post_tls_capabilities: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "mode": self.mode,
            "connection_status": self.connection_status,
            "probe_started_at": self.probe_started_at,
            "probe_completed_at": self.probe_completed_at,
            "requested_hostname": self.requested_hostname,
            "connected_ip": self.connected_ip,
            "latency_ms": self.latency_ms,
            "banner": self.banner,
            "capabilities": self.capabilities,
            "starttls_status": self.starttls_status,
            "starttls_advertised": self.starttls_advertised,
            "starttls_attempted": self.starttls_attempted,
            "starttls_accepted": self.starttls_accepted,
            "response_truncated": self.response_truncated,
            "tls": self.tls.to_dict() if self.tls else None,
            "certificate": self.certificate.to_dict() if self.certificate else None,
            "post_tls_capabilities": self.post_tls_capabilities,
            "limitations": self.limitations,
            "error_message": self.error_message,
        }


@dataclass
class ActiveMailScanReport:
    source: str = "ACTIVE_NETWORK_PROBE"
    historical_applicability: str = "CURRENT_STATE_ONLY"
    requested_hostname: str = ""
    connected_ip: Optional[str] = None
    scan_timestamp_iso: str = ""
    ports: List[int] = field(default_factory=list)
    port_results: List[PortProbeResult] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "historical_applicability": self.historical_applicability,
            "target": self.requested_hostname,
            "requested_hostname": self.requested_hostname,
            "target_ip": self.connected_ip,
            "connected_ip": self.connected_ip,
            "scan_timestamp_iso": self.scan_timestamp_iso,
            "ports": self.ports,
            "port_results": [r.to_dict() for r in self.port_results],
            "findings": self.findings,
            "limitations": self.limitations,
        }


class MailPostureScanner:
    """Safe, strictly bounded, opt-in mail server posture scanner with DNS pinning and strict TLS trust semantics."""

    @classmethod
    def scan(
        cls,
        target: str,
        ports: Optional[List[int]] = None,
        timeout_sec: float = DEFAULT_TIMEOUT_SEC,
        allow_local_testing: bool = False,
        validate_cert_trust: bool = False,
        socket_factory=None,
    ) -> ActiveMailScanReport:
        """
        Executes safe active probes against requested mail service ports on target.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        report = ActiveMailScanReport(
            requested_hostname=target,
            scan_timestamp_iso=now_iso,
            limitations=[
                "Active probes represent CURRENT_STATE_ONLY and do NOT reflect past packet captures.",
                "No authentication commands (AUTH/LOGIN/USER/PASS) were issued.",
                "No email messages (MAIL FROM/RCPT TO/DATA) were transmitted.",
                "Failures indicate network/service unavailability, not historical security posture.",
            ],
        )

        # 1. Target and SSRF validation + Single DNS resolution (DNS Pinning)
        is_safe, primary_ip, err_reason, all_ips = TargetValidator.is_safe_public_target(
            target, allow_local_testing=allow_local_testing
        )
        if not is_safe:
            report.connected_ip = None
            report.limitations.append(f"Target validation failed: {err_reason}")
            requested_ports, _ = TargetValidator.validate_ports_list(ports)
            report.ports = requested_ports
            for p in requested_ports:
                proto, mode = PORT_PROTOCOL_MAP.get(p, ("UNKNOWN", "UNKNOWN"))
                res = PortProbeResult(
                    port=p,
                    protocol=proto,
                    mode=mode,
                    connection_status="RESOLUTION_FAILED",
                    probe_started_at=now_iso,
                    probe_completed_at=now_iso,
                    requested_hostname=target,
                    connected_ip=None,
                    error_message=err_reason,
                    limitations=["Target rejected by SSRF / safety validator."],
                )
                report.port_results.append(res)
            return report

        report.connected_ip = primary_ip

        # 2. Port list validation
        valid_ports, port_err = TargetValidator.validate_ports_list(ports)
        if port_err:
            report.limitations.append(f"Port validation error: {port_err}")
            return report

        report.ports = valid_ports

        # 3. Execute bounded probe per port (strictly pinned to primary_ip)
        all_findings: List[Dict[str, Any]] = []
        for port in valid_ports:
            res = cls.probe_port(
                target=target,
                resolved_ip=primary_ip,
                port=port,
                timeout_sec=min(timeout_sec, DEFAULT_TIMEOUT_SEC),
                validate_cert_trust=validate_cert_trust,
                socket_factory=socket_factory,
            )
            report.port_results.append(res)

            # Generate active findings if applicable
            port_findings = cls._evaluate_active_findings(res)
            all_findings.extend(port_findings)

        report.findings = all_findings
        return report

    @classmethod
    def probe_port(
        cls,
        target: str,
        resolved_ip: Optional[str],
        port: int,
        timeout_sec: float = DEFAULT_TIMEOUT_SEC,
        validate_cert_trust: bool = False,
        socket_factory=None,
    ) -> PortProbeResult:
        """
        Probes a single mail port according to its protocol specification.
        DNS Pinning: Connects directly to resolved_ip, while retaining target hostname for SNI.
        """
        proto, mode = PORT_PROTOCOL_MAP.get(port, ("UNKNOWN", "UNKNOWN"))
        start_time = datetime.now(timezone.utc)
        start_iso = start_time.isoformat()

        # Enforce connection pinning to pre-validated IP
        connect_host = resolved_ip if resolved_ip else target

        result = PortProbeResult(
            port=port,
            protocol=proto,
            mode=mode,
            connection_status="CONNECTION_FAILED",
            probe_started_at=start_iso,
            probe_completed_at=start_iso,
            requested_hostname=target,
            connected_ip=connect_host,
            limitations=[
                "Probe strictly bounded; no credentials or mail data sent.",
                "Represents current network observation only.",
            ],
        )

        # Establish TCP connection directly to pinned IP
        sock = None
        try:
            if socket_factory:
                sock = socket_factory(connect_host, port, timeout_sec)
            else:
                sock = socket.create_connection((connect_host, port), timeout=timeout_sec)
                sock.settimeout(timeout_sec)
        except socket.timeout:
            end_time = datetime.now(timezone.utc)
            result.connection_status = "TIMEOUT"
            result.probe_completed_at = end_time.isoformat()
            result.error_message = f"Connection timed out after {timeout_sec}s."
            return result
        except (ConnectionRefusedError, socket.error) as e:
            end_time = datetime.now(timezone.utc)
            result.connection_status = "CONNECTION_FAILED"
            result.probe_completed_at = end_time.isoformat()
            result.error_message = f"Connection refused / failed: {str(e)}"
            return result
        except Exception as e:
            end_time = datetime.now(timezone.utc)
            result.connection_status = "CONNECTION_FAILED"
            result.probe_completed_at = end_time.isoformat()
            result.error_message = f"Socket error: {str(e)}"
            return result

        # Measure connection latency
        connected_time = datetime.now(timezone.utc)
        result.latency_ms = round((connected_time - start_time).total_seconds() * 1000.0, 2)
        result.connection_status = "SUCCESS"

        try:
            if mode == "DIRECT_TLS":
                cls._probe_direct_tls(
                    sock=sock,
                    target=target,
                    port=port,
                    proto=proto,
                    result=result,
                    validate_cert_trust=validate_cert_trust,
                    timeout_sec=timeout_sec,
                    probe_time=start_iso,
                )
            elif proto == "SMTP" and mode == "STARTTLS":
                cls._probe_smtp_starttls(
                    sock=sock,
                    target=target,
                    port=port,
                    result=result,
                    validate_cert_trust=validate_cert_trust,
                    timeout_sec=timeout_sec,
                    probe_time=start_iso,
                )
            elif proto == "IMAP" and mode == "STARTTLS":
                cls._probe_imap_starttls(
                    sock=sock,
                    target=target,
                    port=port,
                    result=result,
                    validate_cert_trust=validate_cert_trust,
                    timeout_sec=timeout_sec,
                    probe_time=start_iso,
                )
            elif proto == "POP3" and mode == "STLS":
                cls._probe_pop3_stls(
                    sock=sock,
                    target=target,
                    port=port,
                    result=result,
                    validate_cert_trust=validate_cert_trust,
                    timeout_sec=timeout_sec,
                    probe_time=start_iso,
                )
        except socket.timeout:
            result.connection_status = "TIMEOUT"
            result.error_message = "Socket operation timed out during protocol exchange."
        except ssl.CertificateError as e:
            result.connection_status = "TLS_VERIFICATION_FAILED"
            result.error_message = f"TLS hostname mismatch: {str(e)}"
            if result.certificate:
                result.certificate.trust_status = "HOSTNAME_MISMATCH"
                result.certificate.hostname_validated = False
        except ssl.SSLCertVerificationError as e:
            result.connection_status = "TLS_VERIFICATION_FAILED"
            if "hostname" in str(e).lower() or "doesn't match" in str(e).lower() or "match" in str(e).lower():
                result.error_message = f"TLS hostname mismatch: {str(e)}"
                if result.certificate:
                    result.certificate.trust_status = "HOSTNAME_MISMATCH"
                    result.certificate.hostname_validated = False
            else:
                result.error_message = f"TLS certificate verification failed: {str(e)}"
                if result.certificate:
                    result.certificate.trust_status = "TRUST_FAILED"
                    result.certificate.ca_chain_validated = False
        except Exception as e:
            result.error_message = f"Protocol probe error: {str(e)}"
        finally:
            try:
                sock.close()
            except Exception:
                pass

        end_time = datetime.now(timezone.utc)
        result.probe_completed_at = end_time.isoformat()
        return result

    @classmethod
    def _probe_direct_tls(
        cls,
        sock: Any,
        target: str,
        port: int,
        proto: str,
        result: PortProbeResult,
        validate_cert_trust: bool,
        timeout_sec: float,
        probe_time: str,
    ):
        """Probes SMTPS (465), IMAPS (993), or POP3S (995) via direct TLS wrap with SNI."""
        tls_ctx, mode_str = cls._create_ssl_context(validate_cert_trust)
        sni_hostname = target if not cls._is_ip_literal(target) else None

        tls_sock = tls_ctx.wrap_socket(sock, server_hostname=sni_hostname)
        try:
            tls_ver = tls_sock.version()
            cipher_tuple = tls_sock.cipher()
            cipher_str = cipher_tuple[0] if cipher_tuple else None

            result.tls = TLSPostureDetails(
                negotiated_version=tls_ver,
                selected_cipher=cipher_str,
                cipher_posture=cls._classify_cipher_posture(cipher_str),
            )

            # Certificate extraction
            der_cert = tls_sock.getpeercert(binary_form=True)
            if der_cert:
                result.certificate = cls._parse_certificate(
                    der_cert,
                    trust_mode=mode_str,
                    probe_time=probe_time,
                )

            # Protocol greeting / capability over TLS
            if proto == "SMTP":
                banner, _ = cls._recv_bounded_lines(tls_sock, max_lines=5)
                if banner:
                    result.banner = banner.strip()
                tls_sock.sendall(f"EHLO {SAFE_CLIENT_ID}\r\n".encode("utf-8"))
                ehlo_resp, is_trunc = cls._recv_bounded_lines(tls_sock, max_lines=30)
                result.response_truncated = is_trunc
                result.capabilities = cls._parse_smtp_capabilities(ehlo_resp)
            elif proto == "IMAP":
                greeting, _ = cls._recv_bounded_lines(tls_sock, max_lines=3)
                if greeting:
                    result.banner = greeting.strip()
                tls_sock.sendall(b"a001 CAPABILITY\r\n")
                cap_resp, is_trunc = cls._recv_bounded_lines(tls_sock, max_lines=15)
                result.response_truncated = is_trunc
                result.capabilities = cls._parse_imap_capabilities(cap_resp)
            elif proto == "POP3":
                greeting, _ = cls._recv_bounded_lines(tls_sock, max_lines=3)
                if greeting:
                    result.banner = greeting.strip()
                tls_sock.sendall(b"CAPA\r\n")
                capa_resp, is_trunc = cls._recv_bounded_lines(tls_sock, max_lines=20)
                result.response_truncated = is_trunc
                result.capabilities = cls._parse_pop3_capabilities(capa_resp)
        finally:
            try:
                tls_sock.close()
            except Exception:
                pass

    @classmethod
    def _probe_smtp_starttls(
        cls,
        sock: Any,
        target: str,
        port: int,
        result: PortProbeResult,
        validate_cert_trust: bool,
        timeout_sec: float,
        probe_time: str,
    ):
        """Probes SMTP 25 / 587: Read banner -> EHLO -> STARTTLS -> Upgrade -> Post-TLS EHLO."""
        # 1. Read greeting banner
        banner, _ = cls._recv_bounded_lines(sock, max_lines=5)
        if banner:
            result.banner = banner.strip()

        # 2. Safe EHLO
        sock.sendall(f"EHLO {SAFE_CLIENT_ID}\r\n".encode("utf-8"))
        ehlo_resp, is_trunc = cls._recv_bounded_lines(sock, max_lines=30)
        result.response_truncated = is_trunc
        caps = cls._parse_smtp_capabilities(ehlo_resp)
        result.capabilities = caps

        has_starttls = any("STARTTLS" in c.upper() for c in caps) or "STARTTLS" in ehlo_resp.upper()

        if is_trunc and not has_starttls:
            result.starttls_status = "PROBE_INCOMPLETE"
            result.limitations.append("EHLO response was truncated before complete capability enumeration.")
            return

        result.starttls_advertised = has_starttls

        if not has_starttls:
            result.starttls_status = "STARTTLS_NOT_ADVERTISED"
            return

        result.starttls_status = "STARTTLS_ADVERTISED"
        result.starttls_attempted = True

        # 3. Send STARTTLS command
        sock.sendall(b"STARTTLS\r\n")
        starttls_resp_raw, _ = cls._recv_bounded_lines(sock, max_lines=3)
        starttls_resp = starttls_resp_raw.strip()

        if starttls_resp.startswith("220"):
            result.starttls_accepted = True
            result.starttls_status = "STARTTLS_ACCEPTED"

            # Upgrade socket to TLS with SNI
            tls_ctx, mode_str = cls._create_ssl_context(validate_cert_trust)
            sni_hostname = target if not cls._is_ip_literal(target) else None
            tls_sock = tls_ctx.wrap_socket(sock, server_hostname=sni_hostname)
            try:
                result.tls = TLSPostureDetails(
                    negotiated_version=tls_sock.version(),
                    selected_cipher=tls_sock.cipher()[0] if tls_sock.cipher() else None,
                    cipher_posture=cls._classify_cipher_posture(tls_sock.cipher()[0] if tls_sock.cipher() else None),
                )
                der_cert = tls_sock.getpeercert(binary_form=True)
                if der_cert:
                    result.certificate = cls._parse_certificate(
                        der_cert,
                        trust_mode=mode_str,
                        probe_time=probe_time,
                    )

                # Safe post-TLS EHLO
                try:
                    tls_sock.sendall(f"EHLO {SAFE_CLIENT_ID}\r\n".encode("utf-8"))
                    post_ehlo, _ = cls._recv_bounded_lines(tls_sock, max_lines=30)
                    result.post_tls_capabilities = cls._parse_smtp_capabilities(post_ehlo)
                except Exception:
                    pass
            finally:
                try:
                    tls_sock.close()
                except Exception:
                    pass
        else:
            result.starttls_accepted = False
            result.starttls_status = "STARTTLS_REJECTED"
            result.error_message = f"STARTTLS rejected with response: {starttls_resp}"

    @classmethod
    def _probe_imap_starttls(
        cls,
        sock: Any,
        target: str,
        port: int,
        result: PortProbeResult,
        validate_cert_trust: bool,
        timeout_sec: float,
        probe_time: str,
    ):
        """Probes IMAP 143: Read greeting -> CAPABILITY -> STARTTLS -> Upgrade -> CAPABILITY."""
        # 1. Read greeting
        greeting, _ = cls._recv_bounded_lines(sock, max_lines=3)
        if greeting:
            result.banner = greeting.strip()

        # 2. CAPABILITY
        sock.sendall(b"a001 CAPABILITY\r\n")
        cap_resp, is_trunc = cls._recv_bounded_lines(sock, max_lines=15)
        result.response_truncated = is_trunc
        caps = cls._parse_imap_capabilities(cap_resp)
        result.capabilities = caps

        has_starttls = any("STARTTLS" in c.upper() for c in caps) or "STARTTLS" in cap_resp.upper()

        if is_trunc and not has_starttls:
            result.starttls_status = "PROBE_INCOMPLETE"
            result.limitations.append("IMAP capability response was truncated before complete enumeration.")
            return

        result.starttls_advertised = has_starttls

        if not has_starttls:
            result.starttls_status = "STARTTLS_NOT_ADVERTISED"
            return

        result.starttls_status = "STARTTLS_ADVERTISED"
        result.starttls_attempted = True

        # 3. Issue STARTTLS
        sock.sendall(b"a002 STARTTLS\r\n")
        stls_resp_raw, _ = cls._recv_bounded_lines(sock, max_lines=3)
        stls_resp = stls_resp_raw.strip()

        if "A002 OK" in stls_resp.upper() or stls_resp.upper().startswith("OK") or " OK" in stls_resp.upper():
            result.starttls_accepted = True
            result.starttls_status = "STARTTLS_ACCEPTED"

            # Upgrade TLS with SNI
            tls_ctx, mode_str = cls._create_ssl_context(validate_cert_trust)
            sni_hostname = target if not cls._is_ip_literal(target) else None
            tls_sock = tls_ctx.wrap_socket(sock, server_hostname=sni_hostname)
            try:
                result.tls = TLSPostureDetails(
                    negotiated_version=tls_sock.version(),
                    selected_cipher=tls_sock.cipher()[0] if tls_sock.cipher() else None,
                    cipher_posture=cls._classify_cipher_posture(tls_sock.cipher()[0] if tls_sock.cipher() else None),
                )
                der_cert = tls_sock.getpeercert(binary_form=True)
                if der_cert:
                    result.certificate = cls._parse_certificate(
                        der_cert,
                        trust_mode=mode_str,
                        probe_time=probe_time,
                    )

                # Post-TLS CAPABILITY
                try:
                    tls_sock.sendall(b"a003 CAPABILITY\r\n")
                    post_cap, _ = cls._recv_bounded_lines(tls_sock, max_lines=15)
                    result.post_tls_capabilities = cls._parse_imap_capabilities(post_cap)
                except Exception:
                    pass
            finally:
                try:
                    tls_sock.close()
                except Exception:
                    pass
        else:
            result.starttls_accepted = False
            result.starttls_status = "STARTTLS_REJECTED"
            result.error_message = f"IMAP STARTTLS rejected with response: {stls_resp}"

    @classmethod
    def _probe_pop3_stls(
        cls,
        sock: Any,
        target: str,
        port: int,
        result: PortProbeResult,
        validate_cert_trust: bool,
        timeout_sec: float,
        probe_time: str,
    ):
        """Probes POP3 110: Read greeting -> CAPA -> STLS -> Upgrade -> CAPA."""
        # 1. Read greeting
        greeting, _ = cls._recv_bounded_lines(sock, max_lines=3)
        if greeting:
            result.banner = greeting.strip()

        # 2. CAPA
        sock.sendall(b"CAPA\r\n")
        capa_resp, is_trunc = cls._recv_bounded_lines(sock, max_lines=20)
        result.response_truncated = is_trunc
        caps = cls._parse_pop3_capabilities(capa_resp)
        result.capabilities = caps

        has_stls = any("STLS" in c.upper() for c in caps) or "STLS" in capa_resp.upper()

        if is_trunc and not has_stls:
            result.starttls_status = "PROBE_INCOMPLETE"
            result.limitations.append("POP3 CAPA response was truncated before complete enumeration.")
            return

        result.starttls_advertised = has_stls

        if not has_stls:
            result.starttls_status = "STARTTLS_NOT_ADVERTISED"
            return

        result.starttls_status = "STARTTLS_ADVERTISED"
        result.starttls_attempted = True

        # 3. Send STLS
        sock.sendall(b"STLS\r\n")
        stls_resp_raw, _ = cls._recv_bounded_lines(sock, max_lines=3)
        stls_resp = stls_resp_raw.strip()

        if stls_resp.startswith("+OK"):
            result.starttls_accepted = True
            result.starttls_status = "STARTTLS_ACCEPTED"

            # Upgrade TLS with SNI
            tls_ctx, mode_str = cls._create_ssl_context(validate_cert_trust)
            sni_hostname = target if not cls._is_ip_literal(target) else None
            tls_sock = tls_ctx.wrap_socket(sock, server_hostname=sni_hostname)
            try:
                result.tls = TLSPostureDetails(
                    negotiated_version=tls_sock.version(),
                    selected_cipher=tls_sock.cipher()[0] if tls_sock.cipher() else None,
                    cipher_posture=cls._classify_cipher_posture(tls_sock.cipher()[0] if tls_sock.cipher() else None),
                )
                der_cert = tls_sock.getpeercert(binary_form=True)
                if der_cert:
                    result.certificate = cls._parse_certificate(
                        der_cert,
                        trust_mode=mode_str,
                        probe_time=probe_time,
                    )

                # Post-TLS CAPA
                try:
                    tls_sock.sendall(b"CAPA\r\n")
                    post_capa, _ = cls._recv_bounded_lines(tls_sock, max_lines=20)
                    result.post_tls_capabilities = cls._parse_pop3_capabilities(post_capa)
                except Exception:
                    pass
            finally:
                try:
                    tls_sock.close()
                except Exception:
                    pass
        else:
            result.starttls_accepted = False
            result.starttls_status = "STARTTLS_REJECTED"
            result.error_message = f"POP3 STLS rejected with response: {stls_resp}"

    # -------------------------------------------------------------------------
    # Safe Helpers & Parsing
    # -------------------------------------------------------------------------

    @staticmethod
    def _create_ssl_context(validate_cert_trust: bool) -> Tuple[ssl.SSLContext, str]:
        """
        Creates an SSLContext.
        - Default forensic discovery mode: CERT_NONE with trust_validation_mode="NOT_VALIDATED".
        - CA and Hostname verification mode: CERT_REQUIRED with trust_validation_mode="CA_AND_HOSTNAME".
        """
        if validate_cert_trust:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            return ctx, "CA_AND_HOSTNAME"
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx, "NOT_VALIDATED"

    @staticmethod
    def _recv_bounded_lines(sock: Any, max_lines: int = 20, max_bytes: int = MAX_RESPONSE_BYTES) -> Tuple[str, bool]:
        """
        Safely reads bounded lines from a socket up to max_lines and max_bytes.
        Returns (decoded_text, is_truncated).
        """
        received_bytes = bytearray()
        lines_count = 0
        sock.settimeout(DEFAULT_TIMEOUT_SEC)
        is_truncated = False

        while len(received_bytes) < max_bytes and lines_count < max_lines:
            try:
                chunk = sock.recv(min(512, max_bytes - len(received_bytes)))
                if not chunk:
                    break
                received_bytes.extend(chunk)
                lines_count = received_bytes.count(b"\n")
                if b"\r\n.\r\n" in received_bytes or b"\n.\n" in received_bytes:
                    break
                if len(chunk) < 512:
                    break
            except (socket.timeout, ssl.SSLError):
                break
            except Exception:
                break

        if len(received_bytes) >= max_bytes or lines_count >= max_lines:
            is_truncated = True

        return received_bytes.decode("utf-8", errors="ignore"), is_truncated

    @classmethod
    def _parse_certificate(
        cls,
        der_bytes: bytes,
        trust_mode: str = "NOT_VALIDATED",
        probe_time: Optional[str] = None,
    ) -> CertificateDetails:
        """Parses X.509 certificate fields from active TLS handshake using ACTIVE_PROBE_TIME."""
        cert = x509.load_der_x509_certificate(der_bytes)
        now_dt = datetime.fromisoformat(probe_time) if probe_time else datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()

        # Subject & Issuer
        subject_str = cert.subject.rfc4514_string()
        issuer_str = cert.issuer.rfc4514_string()

        # Validity evaluated strictly against ACTIVE_PROBE_TIME
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        is_expired = now_dt > not_after or now_dt < not_before

        # Public key
        pub_key = cert.public_key()
        pub_key_alg = type(pub_key).__name__
        key_size = None
        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_key_alg = "RSA"
            key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key_alg = "ECDSA / EC"
            key_size = pub_key.curve.key_size
        elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pub_key_alg = "EdDSA"
        elif isinstance(pub_key, dsa.DSAPublicKey):
            pub_key_alg = "DSA"
            key_size = pub_key.key_size

        sig_alg = (
            cert.signature_algorithm_oid._name
            if hasattr(cert.signature_algorithm_oid, "_name")
            else str(cert.signature_algorithm_oid)
        )
        sha256_fp = hashlib.sha256(der_bytes).hexdigest()

        # SANs
        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                san_list.append(str(name.value))
        except Exception:
            pass

        self_issued = cert.subject == cert.issuer

        # Trust status breakdown
        ca_chain_val = True if trust_mode in ["CA_CHAIN_ONLY", "CA_AND_HOSTNAME"] else None
        hostname_val = True if trust_mode == "CA_AND_HOSTNAME" else None
        trust_status = "VALIDATED" if trust_mode == "CA_AND_HOSTNAME" else "NOT_VALIDATED"

        return CertificateDetails(
            subject=subject_str,
            issuer=issuer_str,
            not_before=not_before.isoformat(),
            not_after=not_after.isoformat(),
            public_key_algorithm=pub_key_alg,
            public_key_bits=key_size,
            signature_algorithm=sig_alg,
            sha256_fingerprint=sha256_fp,
            trust_validation_mode=trust_mode,
            ca_chain_validated=ca_chain_val,
            hostname_validated=hostname_val,
            trust_status=trust_status,
            is_expired=is_expired,
            validity_reference_time=now_iso,
            reference_time_source="ACTIVE_PROBE_TIME",
            self_issued=self_issued,
            san_list=san_list,
        )

    @staticmethod
    def _is_ip_literal(target: str) -> bool:
        try:
            ipaddress.ip_address(target.strip("[]"))
            return True
        except ValueError:
            return False

    @staticmethod
    def _classify_cipher_posture(cipher_str: Optional[str]) -> str:
        """Deterministically classifies cipher posture without false positives on unknown ciphers."""
        if not cipher_str:
            return "UNKNOWN_POSTURE"

        c_upper = cipher_str.upper()

        # Known weak / broken cipher algorithms & modes
        known_weak_patterns = [
            "RC4", "3DES", "DES", "RC2", "IDEA", "NULL", "EXPORT", "ANON", "ADH", "AECDH", "_MD5",
        ]
        if any(p in c_upper for p in known_weak_patterns):
            return "WEAK"

        # Modern standard ciphers
        known_standard_patterns = [
            "AES", "CHACHA20", "ARIA", "CAMELLIA", "GCM", "CCM", "POLY1305", "SHA256", "SHA384"
        ]
        if any(p in c_upper for p in known_standard_patterns):
            return "STANDARD"

        return "UNKNOWN_POSTURE"

    @staticmethod
    def _parse_smtp_capabilities(resp: str) -> List[str]:
        caps = []
        for line in resp.splitlines():
            line_str = line.strip()
            if line_str.startswith("250-") or line_str.startswith("250 "):
                cap = line_str[4:].strip()
                if cap and not cap.startswith("mail.") and not cap.startswith("smtp."):
                    caps.append(cap)
        return caps

    @staticmethod
    def _parse_imap_capabilities(resp: str) -> List[str]:
        caps = []
        for line in resp.splitlines():
            line_str = line.strip()
            if "* CAPABILITY" in line_str.upper():
                parts = line_str.split()[2:]
                caps.extend(parts)
            elif line_str.startswith("a001 OK") or line_str.startswith("a003 OK"):
                if "[CAPABILITY" in line_str.upper():
                    idx = line_str.upper().find("[CAPABILITY")
                    sub = line_str[idx + 11 :].split("]")[0]
                    caps.extend(sub.split())
        return list(dict.fromkeys(caps))

    @staticmethod
    def _parse_pop3_capabilities(resp: str) -> List[str]:
        caps = []
        for line in resp.splitlines():
            line_str = line.strip()
            if line_str and not line_str.startswith("+OK") and line_str != ".":
                caps.append(line_str)
        return caps

    # -------------------------------------------------------------------------
    # Active Findings Evaluation (Current State Only)
    # -------------------------------------------------------------------------

    @classmethod
    def _evaluate_active_findings(cls, res: PortProbeResult) -> List[Dict[str, Any]]:
        findings = []

        if res.connection_status != "SUCCESS":
            return findings

        # STARTTLS findings
        if res.mode in ["STARTTLS", "STLS"]:
            if res.starttls_status == "STARTTLS_NOT_ADVERTISED" and res.port != 25:
                findings.append({
                    "id": f"ACTIVE-STARTTLS-NOT-ADVERTISED-PORT-{res.port}",
                    "title": f"STARTTLS Not Advertised on Port {res.port} ({res.protocol})",
                    "severity": "HIGH",
                    "source": "ACTIVE_NETWORK_PROBE",
                    "historical_applicability": "CURRENT_STATE_ONLY",
                    "description": f"Port {res.port} is currently reachable but did not advertise STARTTLS/STLS capability.",
                })
            elif res.starttls_status == "STARTTLS_REJECTED":
                findings.append({
                    "id": f"ACTIVE-STARTTLS-REJECTED-PORT-{res.port}",
                    "title": f"STARTTLS Command Rejected on Port {res.port} ({res.protocol})",
                    "severity": "HIGH",
                    "source": "ACTIVE_NETWORK_PROBE",
                    "historical_applicability": "CURRENT_STATE_ONLY",
                    "description": f"Port {res.port} advertised STARTTLS, but the server rejected the STARTTLS upgrade command.",
                })

        # TLS posture findings
        if res.tls:
            tls_ver = res.tls.negotiated_version or ""
            if tls_ver in ["TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"]:
                findings.append({
                    "id": f"ACTIVE-TLS-DEPRECATED-PORT-{res.port}",
                    "title": f"Deprecated TLS Version Negotiated ({tls_ver})",
                    "severity": "CRITICAL",
                    "source": "ACTIVE_NETWORK_PROBE",
                    "historical_applicability": "CURRENT_STATE_ONLY",
                    "description": f"Active probe on port {res.port} negotiated obsolete protocol version {tls_ver}.",
                })

            if res.tls.cipher_posture == "WEAK":
                findings.append({
                    "id": f"ACTIVE-WEAK-CIPHER-PORT-{res.port}",
                    "title": f"Weak Cipher Suite Selected ({res.tls.selected_cipher})",
                    "severity": "HIGH",
                    "source": "ACTIVE_NETWORK_PROBE",
                    "historical_applicability": "CURRENT_STATE_ONLY",
                    "description": f"Active TLS handshake negotiated weak or deprecated cipher suite {res.tls.selected_cipher}.",
                })

        # Certificate findings
        if res.certificate:
            if res.certificate.is_expired:
                findings.append({
                    "id": f"ACTIVE-CERTIFICATE-EXPIRED-PORT-{res.port}",
                    "title": f"X.509 Certificate Expired on Port {res.port}",
                    "severity": "CRITICAL",
                    "source": "ACTIVE_NETWORK_PROBE",
                    "historical_applicability": "CURRENT_STATE_ONLY",
                    "description": f"Observed X.509 certificate validity window ({res.certificate.not_before} to {res.certificate.not_after}) is expired or invalid at probe time.",
                })

            if (
                res.certificate.public_key_algorithm == "RSA"
                and res.certificate.public_key_bits
                and res.certificate.public_key_bits < 2048
            ):
                findings.append({
                    "id": f"ACTIVE-WEAK-RSA-PORT-{res.port}",
                    "title": f"Weak RSA Key Size ({res.certificate.public_key_bits} bits) on Port {res.port}",
                    "severity": "HIGH",
                    "source": "ACTIVE_NETWORK_PROBE",
                    "historical_applicability": "CURRENT_STATE_ONLY",
                    "description": f"Active certificate uses RSA key length of {res.certificate.public_key_bits} bits, below the 2048-bit minimum security standard.",
                })

        return findings
