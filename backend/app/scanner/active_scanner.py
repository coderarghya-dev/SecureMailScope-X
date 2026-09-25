"""
SecureMailScope X - Active Mail Server Security Probe Scanner (Phase 9 Wrapper)
Maintains backward compatibility while delegating to MailPostureScanner.
"""

from typing import List, Dict, Any, Optional
from app.scanner.mail_posture_scanner import (
    MailPostureScanner,
    ActiveMailScanReport as NewActiveScanReport,
    PortProbeResult as NewPortProbeResult,
    PORT_PROTOCOL_MAP as PORT_SERVICE_MAP,
    ALLOWED_MAIL_PORTS as MAIL_PORTS,
)


class PortProbeResult:
    def __init__(
        self,
        port: int,
        service: str,
        mode: str,
        is_open: bool,
        greeting_banner: Optional[str] = None,
        starttls_advertised: bool = False,
        tls_version_negotiated: Optional[str] = None,
        cipher_negotiated: Optional[str] = None,
        certificate_info: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
        probe_latency_ms: float = 0.0,
    ):
        self.port = port
        self.service = service
        self.mode = mode
        self.is_open = is_open
        self.greeting_banner = greeting_banner
        self.starttls_advertised = starttls_advertised
        self.tls_version_negotiated = tls_version_negotiated
        self.cipher_negotiated = cipher_negotiated
        self.certificate_info = certificate_info
        self.error_message = error_message
        self.probe_latency_ms = probe_latency_ms


class ActiveScanReport:
    def __init__(
        self,
        target_host: str,
        scan_timestamp_iso: str,
        data_source: str = "Active TCP / TLS Socket Probe",
        port_results: Optional[List[PortProbeResult]] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
    ):
        self.target_host = target_host
        self.scan_timestamp_iso = scan_timestamp_iso
        self.data_source = data_source
        self.port_results = port_results or []
        self.findings = findings or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_host": self.target_host,
            "scan_timestamp_iso": self.scan_timestamp_iso,
            "data_source": self.data_source,
            "port_results": [r.__dict__ for r in self.port_results],
            "findings": self.findings,
        }


class ActiveMailScanner:
    """Legacy wrapper for MailPostureScanner."""

    @classmethod
    def probe_single_port(cls, host: str, port: int, timeout_sec: float = 3.0) -> PortProbeResult:
        new_res = MailPostureScanner.probe_port(
            target=host,
            resolved_ip=None,
            port=port,
            timeout_sec=timeout_sec,
        )
        return PortProbeResult(
            port=new_res.port,
            service=new_res.protocol,
            mode=new_res.mode,
            is_open=(new_res.connection_status == "SUCCESS"),
            greeting_banner=new_res.banner,
            starttls_advertised=new_res.starttls_advertised,
            tls_version_negotiated=new_res.tls.negotiated_version if new_res.tls else None,
            cipher_negotiated=new_res.tls.selected_cipher if new_res.tls else None,
            certificate_info=new_res.certificate.to_dict() if new_res.certificate else None,
            error_message=new_res.error_message,
            probe_latency_ms=new_res.latency_ms,
        )

    @classmethod
    def scan_target(cls, host: str, ports: Optional[List[int]] = None) -> ActiveScanReport:
        report = MailPostureScanner.scan(
            target=host,
            ports=ports,
            allow_local_testing=False,
        )
        legacy_port_results = []
        for r in report.port_results:
            legacy_port_results.append(
                PortProbeResult(
                    port=r.port,
                    service=r.protocol,
                    mode=r.mode,
                    is_open=(r.connection_status == "SUCCESS"),
                    greeting_banner=r.banner,
                    starttls_advertised=r.starttls_advertised,
                    tls_version_negotiated=r.tls.negotiated_version if r.tls else None,
                    cipher_negotiated=r.tls.selected_cipher if r.tls else None,
                    certificate_info=r.certificate.to_dict() if r.certificate else None,
                    error_message=r.error_message,
                    probe_latency_ms=r.latency_ms,
                )
            )

        return ActiveScanReport(
            target_host=report.target,
            scan_timestamp_iso=report.scan_timestamp_iso,
            data_source="Active TCP / TLS Socket Probe",
            port_results=legacy_port_results,
            findings=report.findings,
        )
