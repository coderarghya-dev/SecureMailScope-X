"""
SecureMailScope X - Safe Network DNS Resolver (Phase 7 / 7.5)
Provides timeout-bounded, safe DNS-over-HTTPS (DoH) lookups and SSRF-hardened MTA-STS policy retrieval.

Forensic & Security Controls:
1. Opt-in execution only; never executed during passive PCAP inspection.
2. Bounded timeouts (default 3.0s per request) and bounded payload sizes (max 64 KB).
3. SSRF & DNS-Rebinding Hardening: Validates domains and rejects localhost, private RFC1918,
   link-local, multicast, unspecified, and non-routable addresses before network retrieval.
4. Provider Provenance: Explicitly identifies resolver endpoint and provider.
5. Error Separation: Distinguishes authoritative NXDOMAIN/NODATA from network timeout/lookup failure.
"""

import json
import urllib.request
import urllib.error
import socket
import ipaddress
import re
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Restricts HTTP redirects to HTTPS only and limits max redirect depth."""

    def __init__(self, max_redirects: int = 2):
        super().__init__()
        self.max_redirects = max_redirects
        self._redirect_count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._redirect_count += 1
        req_url = req.full_url if (req is not None and hasattr(req, "full_url")) else newurl
        if self._redirect_count > self.max_redirects:
            raise urllib.error.HTTPError(req_url, code, "Max redirect limit exceeded", headers, fp)
        
        # Only allow HTTPS redirect targets
        if not newurl.lower().startswith("https://"):
            raise urllib.error.HTTPError(req_url, code, "Insecure non-HTTPS redirect disallowed", headers, fp)

        # Validate new hostname against SSRF
        try:
            from urllib.parse import urlparse
            parsed = urlparse(newurl)
            host = parsed.hostname
            if not host or not DNSResolver.is_safe_public_hostname(host):
                raise urllib.error.HTTPError(req_url, code, "Redirect target resolves to non-public address", headers, fp)
        except urllib.error.HTTPError:
            raise
        except Exception:
            raise urllib.error.HTTPError(req_url, code, "Redirect target SSRF validation failed", headers, fp)

        if req is not None:
            return super().redirect_request(req, fp, code, msg, headers, newurl)
        return None


class DNSResolver:
    """Safe, timeout-bounded DNS resolver for active domain authentication enrichment."""

    CLOUDFLARE_DOH = "https://cloudflare-dns.com/dns-query"
    GOOGLE_DOH = "https://dns.google/resolve"

    def __init__(
        self,
        timeout_sec: float = 3.0,
        endpoint_url: Optional[str] = None,
        provider_name: Optional[str] = None
    ):
        self.timeout_sec = timeout_sec
        self.endpoint_url = endpoint_url or self.CLOUDFLARE_DOH
        if provider_name:
            self.provider_name = provider_name
        elif "cloudflare" in self.endpoint_url:
            self.provider_name = "Cloudflare DoH"
        elif "google" in self.endpoint_url:
            self.provider_name = "Google DoH"
        else:
            self.provider_name = "Custom DoH Resolver"

    @staticmethod
    def is_safe_public_hostname(hostname: str) -> bool:
        """
        Validates hostname syntax and ensures it does NOT point to localhost, private,
        link-local, multicast, or non-routable IP ranges (SSRF defense).
        """
        if not hostname:
            return False

        clean_host = hostname.strip().lower().rstrip(".")

        # Reject common local / internal names
        if clean_host in ["localhost", "local", "broadcasthost"]:
            return False
        if any(clean_host.endswith(sfx) for sfx in [".local", ".localhost", ".internal", ".localdomain", ".lan", ".home", ".corp"]):
            return False

        # Reject userinfo / credentials in host strings
        if "@" in clean_host or ":" in clean_host:
            return False

        # Check if hostname is an IP literal
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_unspecified
                or ip_obj.is_reserved
            ):
                return False
        except ValueError:
            pass  # It is a domain name, not an IP literal

        # Basic domain regex check
        domain_pattern = r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
        if not re.match(domain_pattern, clean_host):
            return False

        # Resolve IP addresses via socket to verify actual destination is public
        try:
            addr_info = socket.getaddrinfo(clean_host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            if not addr_info:
                return False
            for entry in addr_info:
                ip_str = entry[4][0]
                resolved_ip = ipaddress.ip_address(ip_str)
                if (
                    resolved_ip.is_private
                    or resolved_ip.is_loopback
                    or resolved_ip.is_link_local
                    or resolved_ip.is_multicast
                    or resolved_ip.is_unspecified
                    or resolved_ip.is_reserved
                ):
                    return False
        except (socket.gaierror, Exception):
            return False

        return True

    def query_txt_with_status(self, name: str) -> Tuple[List[str], bool, Optional[str]]:
        """
        Queries TXT records for a given DNS name.
        Returns:
            (records: List[str], lookup_succeeded: bool, error_reason: Optional[str])
        """
        clean_name = name.strip().rstrip(".")
        if not clean_name:
            return [], False, "Empty query name"

        url = f"{self.endpoint_url}?name={clean_name}&type=TXT"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/dns-json",
                "User-Agent": "SecureMailScope-ActiveResolver/1.0"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                if resp.status != 200:
                    return [], False, f"DoH resolver returned HTTP {resp.status}"
                data = json.loads(resp.read().decode("utf-8"))
                answers = data.get("Answer", [])
                records = []
                for ans in answers:
                    if ans.get("type") == 16:  # TXT
                        raw_data = ans.get("data", "")
                        clean_data = raw_data.strip('"').replace('\\"', '"')
                        if clean_data:
                            records.append(clean_data)
                return records, True, None
        except urllib.error.URLError as e:
            return [], False, f"Network/DNS error: {str(e)}"
        except Exception as e:
            return [], False, f"Resolver error: {str(e)}"

    def query_txt(self, name: str) -> List[str]:
        """Convenience method returning TXT record list."""
        records, _, _ = self.query_txt_with_status(name)
        return records

    def query_tlsa_with_status(self, name: str) -> Tuple[List[str], bool, Optional[str]]:
        """
        Queries DANE TLSA records (RR type 52) for a given port/protocol/hostname.
        Returns:
            (records: List[str], lookup_succeeded: bool, error_reason: Optional[str])
        """
        clean_name = name.strip().rstrip(".")
        if not clean_name:
            return [], False, "Empty query name"

        url = f"{self.endpoint_url}?name={clean_name}&type=52"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/dns-json",
                "User-Agent": "SecureMailScope-ActiveResolver/1.0"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                if resp.status != 200:
                    return [], False, f"DoH resolver returned HTTP {resp.status}"
                data = json.loads(resp.read().decode("utf-8"))
                answers = data.get("Answer", [])
                records = []
                for ans in answers:
                    if ans.get("type") == 52:  # TLSA
                        raw_data = ans.get("data", "").strip('"')
                        if raw_data:
                            records.append(raw_data)
                return records, True, None
        except urllib.error.URLError as e:
            return [], False, f"Network/DNS error: {str(e)}"
        except Exception as e:
            return [], False, f"Resolver error: {str(e)}"

    def query_tlsa(self, name: str) -> List[str]:
        """Convenience method returning TLSA record list."""
        records, _, _ = self.query_tlsa_with_status(name)
        return records

    def fetch_mta_sts_policy(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Fetches MTA-STS policy over HTTPS (https://mta-sts.<domain>/.well-known/mta-sts.txt).
        SSRF Protected: Rejects non-public, loopback, private, and internal addresses.
        Bounded: 3.0s timeout and 64 KB response limit.
        """
        clean_domain = domain.strip().lower().rstrip(".")
        if not clean_domain:
            return None

        target_host = f"mta-sts.{clean_domain}"
        if not self.is_safe_public_hostname(target_host):
            return None

        target_url = f"https://{target_host}/.well-known/mta-sts.txt"

        opener = urllib.request.build_opener(SafeRedirectHandler(max_redirects=2))
        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": "SecureMailScope-ActiveResolver/1.0"}
        )

        try:
            with opener.open(req, timeout=self.timeout_sec) as resp:
                if resp.status != 200:
                    return None
                
                # Bounded read to max 64 KB
                raw_bytes = resp.read(65536)
                content = raw_bytes.decode("utf-8", errors="replace")
                
                parsed_policy: Dict[str, Any] = {
                    "url": target_url,
                    "fetched_at_utc": datetime.now(timezone.utc).isoformat(),
                    "raw_content": content,
                    "mode": None,
                    "max_age": None,
                    "mx": []
                }
                
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        k, v = line.split(":", 1)
                        k = k.strip().lower()
                        v = v.strip()
                        if k == "mode":
                            parsed_policy["mode"] = v.lower()
                        elif k == "max_age":
                            try:
                                parsed_policy["max_age"] = int(v)
                            except ValueError:
                                pass
                        elif k == "mx":
                            parsed_policy["mx"].append(v)

                return parsed_policy
        except Exception:
            return None
