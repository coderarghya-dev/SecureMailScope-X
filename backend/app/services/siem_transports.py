# ==============================================================================
# SecureMailScope X — Phase 19: SIEM / SOC Delivery Transports
# ==============================================================================
"""Transports for dispatching normalized SOC telemetry events to local files,
UDP Syslog, TCP Syslog, and HTTPS JSON Webhooks.
"""

import os
import socket
import urllib.error
import urllib.request
from typing import Optional, Tuple


class BaseSIEMTransport:
    """Base transport interface."""

    def __init__(self, destination_label: str):
        self.destination_label = destination_label

    def deliver(self, payload: str) -> Tuple[bool, Optional[str]]:
        raise NotImplementedError


class LocalFileTransport(BaseSIEMTransport):
    """Offline local file transport."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        super().__init__(destination_label=f"file:{os.path.basename(file_path)}")

    def deliver(self, payload: str) -> Tuple[bool, Optional[str]]:
        try:
            target_dir = os.path.dirname(self.file_path)
            if target_dir:
                os.makedirs(target_dir, exist_ok=True)
            with open(self.file_path, "w", encoding="utf-8") as f:
                f.write(payload)
            return True, None
        except Exception as ex:
            return False, f"Local file write error: {str(ex)}"


class UdpSyslogTransport(BaseSIEMTransport):
    """UDP Syslog transport."""

    def __init__(self, host: str, port: int = 514):
        self.host = host
        self.port = port
        super().__init__(destination_label=f"udp://{host}:{port}")

    def deliver(self, payload: str) -> Tuple[bool, Optional[str]]:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            lines = payload.splitlines()
            for line in lines:
                if line.strip():
                    sock.sendto(line.encode("utf-8"), (self.host, self.port))
            return True, None
        except Exception as ex:
            return False, f"UDP Syslog dispatch error: {str(ex)}"
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass


class TcpSyslogTransport(BaseSIEMTransport):
    """TCP Syslog transport."""

    def __init__(self, host: str, port: int = 6514):
        self.host = host
        self.port = port
        super().__init__(destination_label=f"tcp://{host}:{port}")

    def deliver(self, payload: str) -> Tuple[bool, Optional[str]]:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            lines = payload.splitlines()
            for line in lines:
                if line.strip():
                    sock.sendall((line + "\n").encode("utf-8"))
            return True, None
        except Exception as ex:
            return False, f"TCP Syslog dispatch error: {str(ex)}"
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass


class JsonWebhookTransport(BaseSIEMTransport):
    """HTTPS/HTTP JSON Webhook transport with secret redaction."""

    def __init__(self, url: str, auth_header: Optional[str] = None):
        self.url = url
        self.auth_header = auth_header
        super().__init__(destination_label=url)

    def deliver(self, payload: str) -> Tuple[bool, Optional[str]]:
        try:
            headers = {"Content-Type": "application/json"}
            if self.auth_header:
                headers["Authorization"] = self.auth_header

            req = urllib.request.Request(
                self.url,
                data=payload.encode("utf-8"),
                headers=headers,
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=10) as resp:
                status_code = resp.getcode()
                if 200 <= status_code < 300:
                    return True, None
                else:
                    return False, f"Webhook returned HTTP {status_code}"
        except urllib.error.HTTPError as he:
            err = f"HTTPError: {he.code} {he.reason}"
            if self.auth_header and self.auth_header in err:
                err = err.replace(self.auth_header, "[REDACTED]")
            return False, err
        except Exception as ex:
            err = f"Webhook delivery error: {str(ex)}"
            if self.auth_header and self.auth_header in err:
                err = err.replace(self.auth_header, "[REDACTED]")
            return False, err
