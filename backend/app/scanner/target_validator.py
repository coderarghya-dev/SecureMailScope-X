"""
SecureMailScope X - Active Scanner Target Validator & SSRF Defender (Phase 9 & 9.5)
Validates scan targets, enforces strict port allowlists, and protects against SSRF and DNS rebinding.

Allowed Mail Ports:
- SMTP: 25, 465, 587
- IMAP: 143, 993
- POP3: 110, 995
"""

import socket
import ipaddress
import re
from typing import List, Tuple, Optional, Set

ALLOWED_MAIL_PORTS: Set[int] = {25, 465, 587, 110, 143, 993, 995}

PORT_PROTOCOL_MAP = {
    25: ("SMTP", "STARTTLS"),
    465: ("SMTP", "DIRECT_TLS"),
    587: ("SMTP", "STARTTLS"),
    110: ("POP3", "STLS"),
    143: ("IMAP", "STARTTLS"),
    993: ("IMAP", "DIRECT_TLS"),
    995: ("POP3", "DIRECT_TLS"),
}


class TargetValidator:
    """Validates hostnames, IPs, and ports for the active mail posture scanner."""

    @classmethod
    def validate_port(cls, port: int) -> Tuple[bool, Optional[str]]:
        """Ensures port is within the strictly allowed mail services allowlist."""
        if not isinstance(port, int) or port not in ALLOWED_MAIL_PORTS:
            return False, f"Port {port} is not an allowed mail service port (allowed: {sorted(ALLOWED_MAIL_PORTS)})."
        return True, None

    @classmethod
    def validate_ports_list(cls, ports: Optional[List[int]]) -> Tuple[List[int], Optional[str]]:
        """Validates and filters requested ports list."""
        if not ports:
            return sorted(ALLOWED_MAIL_PORTS), None

        valid_ports: List[int] = []
        for p in ports:
            is_valid, err = cls.validate_port(p)
            if not is_valid:
                return [], err
            if p not in valid_ports:
                valid_ports.append(p)
        return valid_ports, None

    @classmethod
    def is_safe_public_target(
        cls,
        target: str,
        allow_local_testing: bool = False
    ) -> Tuple[bool, Optional[str], Optional[str], List[str]]:
        """
        Validates target syntax and ensures destination does NOT point to localhost,
        private (RFC 1918), link-local, multicast, or non-routable IP ranges (SSRF defense).

        Resolves hostnames once and validates ALL candidate addresses against SSRF constraints.

        Returns:
            (is_safe: bool, primary_ip: Optional[str], error_reason: Optional[str], all_validated_ips: List[str])
        """
        if not target or not isinstance(target, str):
            return False, None, "Target host string is empty.", []

        clean_target = target.strip().lower().rstrip(".")

        # Reject URL schemes, userinfo, paths, query strings, and embedded ports
        if "://" in clean_target:
            return False, None, "URL schemes (e.g. http://, https://) are not allowed; provide hostname or IP only.", []
        if "@" in clean_target:
            return False, None, "Userinfo credentials (@) are not allowed in scan targets.", []
        if "/" in clean_target or "\\" in clean_target:
            return False, None, "URL paths are not allowed in scan targets.", []
        if "?" in clean_target or "#" in clean_target:
            return False, None, "Query strings or fragments are not allowed in scan targets.", []
        if ":" in clean_target and not cls._is_valid_ipv6_literal(clean_target):
            return False, None, "Embedded ports (:port) are not allowed; use the ports parameter.", []

        # If local testing override is explicitly enabled (e.g., test fixtures)
        if allow_local_testing:
            if clean_target in ["localhost", "127.0.0.1", "::1"]:
                return True, "127.0.0.1", None, ["127.0.0.1"]

        # Reject common internal names
        if clean_target in ["localhost", "local", "broadcasthost"]:
            return False, None, "Target points to localhost / loopback address (SSRF blocked).", []
        if any(clean_target.endswith(sfx) for sfx in [".local", ".localhost", ".internal", ".localdomain", ".lan", ".home", ".corp"]):
            return False, None, "Target points to private / internal domain suffix (SSRF blocked).", []

        # Check if target is an IP literal
        try:
            ip_obj = ipaddress.ip_address(clean_target.strip("[]"))
            if not allow_local_testing and (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_unspecified
                or ip_obj.is_reserved
            ):
                return False, None, f"Target IP {clean_target} is private, loopback, or non-routable (SSRF blocked).", []
            return True, str(ip_obj), None, [str(ip_obj)]
        except ValueError:
            pass  # It is a domain name

        # Validate domain syntax
        domain_pattern = r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
        if not re.match(domain_pattern, clean_target):
            return False, None, f"Invalid domain syntax '{clean_target}'.", []

        # Resolve IP addresses via socket getaddrinfo
        try:
            addr_info = socket.getaddrinfo(clean_target, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            if not addr_info:
                return False, None, f"Could not resolve domain '{clean_target}'.", []

            validated_ips: List[str] = []
            for entry in addr_info:
                ip_str = entry[4][0]
                if ip_str in validated_ips:
                    continue

                resolved_ip = ipaddress.ip_address(ip_str)
                if not allow_local_testing and (
                    resolved_ip.is_private
                    or resolved_ip.is_loopback
                    or resolved_ip.is_link_local
                    or resolved_ip.is_multicast
                    or resolved_ip.is_unspecified
                    or resolved_ip.is_reserved
                ):
                    return False, None, f"Domain '{clean_target}' resolves to non-public/private IP {ip_str} (SSRF blocked).", []

                validated_ips.append(ip_str)

            if not validated_ips:
                return False, None, f"No valid addresses found for '{clean_target}'.", []

            return True, validated_ips[0], None, validated_ips
        except socket.gaierror as e:
            return False, None, f"DNS resolution failed for '{clean_target}': {str(e)}", []
        except Exception as e:
            return False, None, f"Target validation error: {str(e)}", []

    @staticmethod
    def _is_valid_ipv6_literal(target: str) -> bool:
        """Checks if a string is a clean IPv6 address literal."""
        try:
            ip = ipaddress.ip_address(target.strip("[]"))
            return ip.version == 6
        except ValueError:
            return False
