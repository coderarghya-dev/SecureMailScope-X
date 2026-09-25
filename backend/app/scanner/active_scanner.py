"""
SecureMailScope X - Active Mail Server Security Probe Scanner
Executes safe active network probes against email services on ports 25, 465, 587, 110, 143, 993, 995.
CRITICAL FORENSIC BOUNDARY: Clearly labeled ACTIVE SECURITY PROBE, strictly separated from passive PCAP.
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from app.tls.cert_analyzer import CertificateAnalyzer, CertificateInfo


MAIL_PORTS = [25, 465, 587, 110, 143, 993, 995]

PORT_SERVICE_MAP = {
    25: ("SMTP", "STARTTLS"),
    465: ("SMTP", "DIRECT_TLS"),
    587: ("SMTP", "STARTTLS"),
    110: ("POP3", "STLS"),
    143: ("IMAP", "STARTTLS"),
    993: ("IMAP", "DIRECT_TLS"),
    995: ("POP3", "DIRECT_TLS"),
}


@dataclass
class PortProbeResult:
    port: int
    service: str
    mode: str
    is_open: bool
    greeting_banner: Optional[str] = None
    starttls_advertised: bool = False
    tls_version_negotiated: Optional[str] = None
    cipher_negotiated: Optional[str] = None
    certificate_info: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    probe_latency_ms: float = 0.0


@dataclass
class ActiveScanReport:
    target_host: str
    scan_timestamp_iso: str
    data_source: str = "Active TCP / TLS Socket Probe"
    port_results: List[PortProbeResult] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_host": self.target_host,
            "scan_timestamp_iso": self.scan_timestamp_iso,
            "data_source": self.data_source,
            "port_results": [r.__dict__ for r in self.port_results],
            "findings": self.findings,
        }


class ActiveMailScanner:
    """Safe, non-destructive active scanner for mail servers."""

    @classmethod
    def probe_single_port(cls, host: str, port: int, timeout_sec: float = 3.0) -> PortProbeResult:
        service, mode = PORT_SERVICE_MAP.get(port, ("UNKNOWN", "UNKNOWN"))
        start_time = datetime.now()

        try:
            sock = socket.create_connection((host, port), timeout=timeout_sec)
            sock.settimeout(timeout_sec)
        except Exception as e:
            return PortProbeResult(
                port=port,
                service=service,
                mode=mode,
                is_open=False,
                error_message=str(e),
            )

        latency = (datetime.now() - start_time).total_seconds() * 1000.0
        greeting = None
        starttls_advertised = False
        tls_ver = None
        cipher_str = None
        cert_info_dict = None

        try:
            if mode == "DIRECT_TLS":
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                tls_sock = context.wrap_socket(sock, server_hostname=host)
                tls_ver = tls_sock.version()
                cipher_tuple = tls_sock.cipher()
                cipher_str = cipher_tuple[0] if cipher_tuple else None

                der_cert = tls_sock.getpeercert(binary_form=True)
                if der_cert:
                    cert_obj = CertificateAnalyzer.parse_der(der_cert, target_hostname=host)
                    cert_info_dict = cert_obj.to_dict()
                tls_sock.close()

            elif mode in ["STARTTLS", "STLS"]:
                try:
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                    greeting = banner
                except Exception:
                    pass

                # Probe STARTTLS/STLS capability
                if port in [25, 587]:
                    try:
                        sock.sendall(b"EHLO securemailscope.probe\r\n")
                        ehlo_resp = sock.recv(2048).decode(errors="ignore")
                        if "STARTTLS" in ehlo_resp.upper():
                            starttls_advertised = True
                    except Exception:
                        pass
                elif port == 110:
                    try:
                        sock.sendall(b"CAPA\r\n")
                        capa_resp = sock.recv(2048).decode(errors="ignore")
                        if "STLS" in capa_resp.upper():
                            starttls_advertised = True
                    except Exception:
                        pass
                elif port == 143:
                    try:
                        sock.sendall(b"a001 CAPABILITY\r\n")
                        capa_resp = sock.recv(2048).decode(errors="ignore")
                        if "STARTTLS" in capa_resp.upper():
                            starttls_advertised = True
                    except Exception:
                        pass
                sock.close()
        except Exception as e:
            pass

        return PortProbeResult(
            port=port,
            service=service,
            mode=mode,
            is_open=True,
            greeting_banner=greeting,
            starttls_advertised=starttls_advertised,
            tls_version_negotiated=tls_ver,
            cipher_negotiated=cipher_str,
            certificate_info=cert_info_dict,
            probe_latency_ms=round(latency, 2),
        )

    @classmethod
    def scan_target(cls, host: str, ports: Optional[List[int]] = None) -> ActiveScanReport:
        target_ports = ports or MAIL_PORTS
        now_iso = datetime.now(timezone.utc).isoformat()
        results: List[PortProbeResult] = []
        findings: List[Dict[str, Any]] = []

        for p in target_ports:
            res = cls.probe_single_port(host, p)
            results.append(res)
            if res.is_open and res.mode == "STARTTLS" and not res.starttls_advertised and res.port != 25:
                findings.append({
                    "id": f"FINDING-SCAN-NO-STARTTLS-PORT-{res.port}",
                    "title": f"Port {res.port} ({res.service}) Missing STARTTLS Advertisement",
                    "severity": "HIGH",
                    "description": f"Port {res.port} is open but did not advertise STARTTLS encryption capability.",
                })

        return ActiveScanReport(
            target_host=host,
            scan_timestamp_iso=now_iso,
            port_results=results,
            findings=findings,
        )
