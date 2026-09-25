"""
SecureMailScope X - Email Header & .EML Forensics Analyzer
Parses RFC 5322 / RFC 822 email headers, extracts Received relay hop chains,
decodes Authentication-Results (SPF/DKIM/DMARC), and detects anomalous/insecure routing.
CRITICAL FORENSIC BOUNDARY: EML evidence is explicitly identified separately from PCAP packet evidence.
"""

import email
from email import policy
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class RelayHop:
    hop_index: int
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    with_protocol: Optional[str] = None
    tls_cipher: Optional[str] = None
    timestamp_raw: Optional[str] = None
    timestamp_iso: Optional[str] = None
    is_tls_encrypted: bool = False
    raw_header: str = ""


@dataclass
class EMLForensicReport:
    message_id: Optional[str] = None
    from_header: Optional[str] = None
    return_path: Optional[str] = None
    to_header: Optional[str] = None
    subject: Optional[str] = None
    date_header_iso: Optional[str] = None
    total_hops: int = 0
    hops: List[RelayHop] = field(default_factory=list)
    auth_results_raw: List[str] = field(default_factory=list)
    spf_auth_result: Optional[str] = None
    dkim_auth_result: Optional[str] = None
    dmarc_auth_result: Optional[str] = None
    has_insecure_hop: bool = False
    inconsistencies: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "from_header": self.from_header,
            "return_path": self.return_path,
            "to_header": self.to_header,
            "subject": self.subject,
            "date_header_iso": self.date_header_iso,
            "total_hops": self.total_hops,
            "hops": [h.__dict__ for h in self.hops],
            "auth_results_raw": self.auth_results_raw,
            "spf_auth_result": self.spf_auth_result,
            "dkim_auth_result": self.dkim_auth_result,
            "dmarc_auth_result": self.dmarc_auth_result,
            "has_insecure_hop": self.has_insecure_hop,
            "inconsistencies": self.inconsistencies,
            "findings": self.findings,
        }


class EMLForensicAnalyzer:
    """Performs static forensic inspection of RFC email messages and header chains."""

    @classmethod
    def parse_eml_content(cls, eml_bytes_or_str: Any) -> EMLForensicReport:
        if isinstance(eml_bytes_or_str, bytes):
            msg = email.message_from_bytes(eml_bytes_or_str, policy=policy.default)
        else:
            msg = email.message_from_string(str(eml_bytes_or_str), policy=policy.default)

        message_id = msg.get("Message-ID")
        from_hdr = msg.get("From")
        return_path = msg.get("Return-Path")
        to_hdr = msg.get("To")
        subject = msg.get("Subject")
        date_hdr = msg.get("Date")

        date_iso = None
        if date_hdr:
            try:
                dt = parsedate_to_datetime(date_hdr)
                date_iso = dt.astimezone(timezone.utc).isoformat()
            except Exception:
                date_iso = str(date_hdr)

        # Parse Received headers (chronological order is bottom-to-top in header list)
        received_headers = msg.get_all("Received", [])
        # Reverse to get chronological hop 1 (first sender) to hop N (final receiver)
        received_chronological = list(reversed(received_headers))

        hops: List[RelayHop] = []
        has_insecure_hop = False

        for idx, raw_rcvd in enumerate(received_chronological, 1):
            clean_rcvd = " ".join(str(raw_rcvd).split())
            
            from_match = re.search(r"from\s+([^\s;()]+(?:\s*\([^)]*\))?)", clean_rcvd, re.IGNORECASE)
            by_match = re.search(r"by\s+([^\s;()]+)", clean_rcvd, re.IGNORECASE)
            with_match = re.search(r"with\s+([^\s;]+)", clean_rcvd, re.IGNORECASE)
            tls_match = re.search(r"(TLS[v0-9_.]*|ESMTPS|cipher=[^\s;]+|using\s+TLS)", clean_rcvd, re.IGNORECASE)

            is_tls = bool(tls_match or (with_match and "ESMTPS" in with_match.group(1).upper()))
            if not is_tls:
                has_insecure_hop = True

            # Extract timestamp after semicolon
            ts_raw = None
            ts_iso = None
            if ";" in clean_rcvd:
                ts_raw = clean_rcvd.split(";")[-1].strip()
                try:
                    dt_hop = parsedate_to_datetime(ts_raw)
                    ts_iso = dt_hop.astimezone(timezone.utc).isoformat()
                except Exception:
                    pass

            hops.append(RelayHop(
                hop_index=idx,
                from_host=from_match.group(1).strip() if from_match else None,
                by_host=by_match.group(1).strip() if by_match else None,
                with_protocol=with_match.group(1).strip() if with_match else None,
                tls_cipher=tls_match.group(0) if tls_match else None,
                timestamp_raw=ts_raw,
                timestamp_iso=ts_iso,
                is_tls_encrypted=is_tls,
                raw_header=clean_rcvd,
            ))

        # Parse Authentication-Results
        auth_results = [str(a) for a in msg.get_all("Authentication-Results", [])]
        spf_res = None
        dkim_res = None
        dmarc_res = None

        for ar in auth_results:
            if "spf=" in ar:
                m = re.search(r"spf=([a-zA-Z0-9]+)", ar)
                if m: spf_res = m.group(1).lower()
            if "dkim=" in ar:
                m = re.search(r"dkim=([a-zA-Z0-9]+)", ar)
                if m: dkim_res = m.group(1).lower()
            if "dmarc=" in ar:
                m = re.search(r"dmarc=([a-zA-Z0-9]+)", ar)
                if m: dmarc_res = m.group(1).lower()

        inconsistencies = []
        findings = []

        # Check From vs Return-Path domain alignment
        if from_hdr and return_path:
            from_domain_match = re.search(r"@([a-zA-Z0-9.-]+)", from_hdr)
            rp_domain_match = re.search(r"@([a-zA-Z0-9.-]+)", return_path)
            if from_domain_match and rp_domain_match:
                from_d = from_domain_match.group(1).lower()
                rp_d = rp_domain_match.group(1).lower()
                if from_d != rp_d and not rp_d.endswith(f".{from_d}") and not from_d.endswith(f".{rp_d}"):
                    inconsistencies.append(f"Domain mismatch between From (@{from_d}) and Return-Path (@{rp_d})")
                    findings.append({
                        "id": "FINDING-EML-RETURN-PATH-MISMATCH",
                        "title": "Sender / Return-Path Domain Inconsistency",
                        "severity": "LOW",
                        "description": f"The RFC header 'From' (@{from_d}) differs from envelope 'Return-Path' (@{rp_d}). Common in mailing lists or spoofing attempts.",
                    })

        if has_insecure_hop:
            findings.append({
                "id": "FINDING-EML-PLAINTEXT-RELAY-HOP",
                "title": "Unencrypted Email Relay Hop in Transit",
                "severity": "MEDIUM",
                "description": "One or more intermediary MTA hops in the Received chain transferred this message without TLS encryption.",
            })

        if dmarc_res == "fail":
            findings.append({
                "id": "FINDING-EML-DMARC-FAIL",
                "title": "Authentication-Results DMARC Verification Failed",
                "severity": "HIGH",
                "description": "Receiving MTA reported DMARC authentication failure for this message.",
            })

        return EMLForensicReport(
            message_id=message_id,
            from_header=from_hdr,
            return_path=return_path,
            to_header=to_hdr,
            subject=subject,
            date_header_iso=date_iso,
            total_hops=len(hops),
            hops=hops,
            auth_results_raw=auth_results,
            spf_auth_result=spf_res,
            dkim_auth_result=dkim_res,
            dmarc_auth_result=dmarc_res,
            has_insecure_hop=has_insecure_hop,
            inconsistencies=inconsistencies,
            findings=findings,
        )
