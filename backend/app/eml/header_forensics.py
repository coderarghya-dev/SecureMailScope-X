"""
SecureMailScope X - RFC 5322 / RFC 822 Email Header Forensics & Relay-Chain Parser (Phase 8 / 8.5)
Extracts structured relay hop chains, asserted authentication headers, DKIM signature metadata,
MIME attachments (with SHA-256 of decoded bytes), and non-speculative header relationships.

Forensic Rules & Boundaries:
1. Parse strictly what is present in the message; never fabricate missing hops, timestamps, or headers.
2. Received headers and Authentication-Results are treated as ASSERTED header evidence, not verified telemetry.
3. Transport security in Received headers is strictly TRI-STATE:
   - ENCRYPTED_ASSERTED (is_tls_encrypted = True): when header explicitly asserts TLS/ESMTPS/SMTPS or cipher.
   - PLAINTEXT_ASSERTED (is_tls_encrypted = False): when header explicitly asserts unencrypted transport (e.g. 'with SMTP').
   - UNKNOWN (is_tls_encrypted = None): when transport security is unstated or ambiguous.
4. DKIM-Signature presence leaves dkim_verification_status = "NOT_VERIFIED" without cryptographic execution.
5. Header domain comparisons use 'matches' and 'different' (avoiding 'aligns' which implies verified DMARC alignment).
6. Malformed dates or Received headers capture parse errors explicitly without silent normalization.
7. Attachments are parsed for metadata and hashed; no file execution or speculative malware classification.
"""

import email
from email import policy
from email.utils import parseaddr, parsedate_to_datetime
import hashlib
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class RelayHop:
    """Structured representation of a single Received header hop."""
    hop_index: int                       # 1-indexed in original header appearance order (top-to-bottom)
    raw_header: str
    from_host: Optional[str] = None
    from_ip: Optional[str] = None
    by_host: Optional[str] = None
    by_ip: Optional[str] = None
    with_protocol: Optional[str] = None
    id: Optional[str] = None
    for_recipient: Optional[str] = None
    tls_cipher: Optional[str] = None
    transport_security_status: str = "UNKNOWN"  # "ENCRYPTED_ASSERTED", "PLAINTEXT_ASSERTED", "UNKNOWN"
    is_tls_encrypted: Optional[bool] = None     # True = encrypted asserted, False = plaintext asserted, None = unknown
    timestamp_raw: Optional[str] = None
    timestamp_iso: Optional[str] = None
    evidence_nature: str = "ASSERTED_HEADER_EVIDENCE"
    parse_status: str = "PARSED"         # "PARSED", "PARTIAL", "MALFORMED"


@dataclass
class HeaderRelationship:
    """Evidence-bounded comparison between two email address headers."""
    comparison: str                      # e.g., "FROM_VS_RETURN_PATH", "FROM_VS_SENDER", "REPLY_TO_VS_FROM", "MESSAGE_ID_VS_FROM"
    header_a_name: str
    header_a_value: Optional[str]
    header_a_domain: Optional[str]
    header_b_name: str
    header_b_value: Optional[str]
    header_b_domain: Optional[str]
    status: str                          # "MATCH", "DIFFERENT", "NOT_PRESENT", "NOT_COMPARABLE"
    description: str                     # Strictly neutral non-speculative explanation


@dataclass
class AssertedAuthResult:
    """Parsed Authentication-Results header (RFC 7601 / RFC 8601)."""
    authserv_id: Optional[str] = None
    raw_header: str = ""
    spf_result: Optional[str] = None
    spf_mailfrom: Optional[str] = None
    spf_reason: Optional[str] = None
    dkim_result: Optional[str] = None
    dkim_domain: Optional[str] = None
    dkim_selector: Optional[str] = None
    dkim_reason: Optional[str] = None
    dmarc_result: Optional[str] = None
    dmarc_from: Optional[str] = None
    dmarc_reason: Optional[str] = None
    arc_result: Optional[str] = None
    evidence_nature: str = "ASSERTED_AUTH_RESULT"
    independent_verification_status: str = "NOT_VERIFIED"


@dataclass
class AssertedReceivedSPF:
    """Parsed Received-SPF header (RFC 7208)."""
    result: Optional[str] = None         # "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"
    client_ip: Optional[str] = None
    envelope_from: Optional[str] = None
    receiver: Optional[str] = None
    identity: Optional[str] = None
    mechanism: Optional[str] = None
    raw_header: str = ""
    evidence_nature: str = "ASSERTED_SPF_RESULT"


@dataclass
class DKIMSignatureMetadata:
    """Extracted metadata tags from a DKIM-Signature header (RFC 6376)."""
    v: Optional[str] = None
    a: Optional[str] = None
    d: Optional[str] = None
    s: Optional[str] = None
    c: Optional[str] = None
    q: Optional[str] = None
    h: Optional[str] = None
    bh: Optional[str] = None
    b: Optional[str] = None
    t: Optional[str] = None
    x: Optional[str] = None
    raw_header: str = ""
    dkim_verification_status: str = "NOT_VERIFIED"
    evidence_nature: str = "ASSERTED_SIGNATURE_METADATA"


@dataclass
class AttachmentMetadata:
    """Safe metadata inspection for email MIME attachments."""
    filename: Optional[str] = None
    content_type: str = "application/octet-stream"
    content_disposition: Optional[str] = None
    transfer_encoding: Optional[str] = None
    size_bytes: int = 0
    attachment_sha256: Optional[str] = None
    hash_source: str = "DECODED_ATTACHMENT_BYTES"


@dataclass
class EMLBodySummary:
    """Structural overview of email body parts."""
    has_text_plain: bool = False
    has_text_html: bool = False
    mime_structure: Optional[str] = None
    total_body_bytes: int = 0
    attachment_count: int = 0


@dataclass
class EMLDateMetadata:
    """Date header parsing with explicit parse error tracking."""
    raw_value: Optional[str] = None
    timestamp_iso: Optional[str] = None
    parse_status: str = "MISSING"        # "VALID", "MALFORMED", "MISSING"


@dataclass
class EMLAddressHeader:
    """Parsed address header (From, Sender, Reply-To, Return-Path)."""
    raw_value: Optional[str] = None
    display_name: Optional[str] = None
    address: Optional[str] = None
    domain: Optional[str] = None


class HeaderForensics:
    """Deterministic parser and forensic relationship evaluator for RFC 5322 email messages."""

    @staticmethod
    def parse_address_header(raw_value: Optional[str]) -> Optional[EMLAddressHeader]:
        """Parses display name, email address, and domain from an RFC 5322 address header."""
        if not raw_value:
            return None
        clean_raw = " ".join(raw_value.split())
        display_name, addr = parseaddr(clean_raw)
        domain = None
        if addr and "@" in addr:
            domain = addr.split("@", 1)[1].lower().strip()
        return EMLAddressHeader(
            raw_value=clean_raw,
            display_name=display_name if display_name else None,
            address=addr if addr else None,
            domain=domain
        )

    @staticmethod
    def parse_date_header(raw_value: Optional[str]) -> EMLDateMetadata:
        """Parses Date header preserving raw text and capturing malformed formats."""
        if not raw_value:
            return EMLDateMetadata(raw_value=None, timestamp_iso=None, parse_status="MISSING")
        clean_raw = " ".join(raw_value.split())
        try:
            dt = parsedate_to_datetime(clean_raw)
            iso_val = dt.astimezone(timezone.utc).isoformat()
            return EMLDateMetadata(raw_value=clean_raw, timestamp_iso=iso_val, parse_status="VALID")
        except Exception:
            return EMLDateMetadata(raw_value=clean_raw, timestamp_iso=None, parse_status="MALFORMED")

    @classmethod
    def parse_received_hop(cls, raw_header: str, index: int) -> RelayHop:
        """
        Parses a single Received header per RFC 5321 / RFC 5322.
        Transport security is evaluated tri-state:
        - ENCRYPTED_ASSERTED: explicit TLS/ESMTPS/SMTPS or cipher asserted
        - PLAINTEXT_ASSERTED: explicit plaintext transport asserted (e.g. 'with SMTP' or 'with ESMTP')
        - UNKNOWN: transport security unstated
        """
        clean_rcvd = " ".join(str(raw_header).split())
        if not clean_rcvd:
            return RelayHop(
                hop_index=index,
                raw_header="",
                transport_security_status="UNKNOWN",
                is_tls_encrypted=None,
                parse_status="MALFORMED"
            )

        from_host = None
        from_ip = None
        by_host = None
        by_ip = None
        with_proto = None
        msg_id = None
        for_recip = None
        tls_cipher = None
        ts_raw = None
        ts_iso = None

        # Split timestamp at last semicolon if present
        content_part = clean_rcvd
        if ";" in clean_rcvd:
            parts = clean_rcvd.rsplit(";", 1)
            content_part = parts[0].strip()
            ts_raw = parts[1].strip()
            try:
                dt_hop = parsedate_to_datetime(ts_raw)
                ts_iso = dt_hop.astimezone(timezone.utc).isoformat()
            except Exception:
                pass

        # Extract "from <host> (<ip>)"
        from_match = re.search(r"\bfrom\s+([^\s;()]+)(?:\s*\(([^)]*)\))?", content_part, re.IGNORECASE)
        if from_match:
            from_host = from_match.group(1).strip()
            from_paren = from_match.group(2)
            if from_paren:
                ip_match = re.search(r"\[([0-9a-fA-F:.]+)\]|(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)", from_paren)
                if ip_match:
                    from_ip = ip_match.group(1) or ip_match.group(2)

        # Extract "by <host> (<ip>)"
        by_match = re.search(r"\bby\s+([^\s;()]+)(?:\s*\(([^)]*)\))?", content_part, re.IGNORECASE)
        if by_match:
            by_host = by_match.group(1).strip()
            by_paren = by_match.group(2)
            if by_paren:
                ip_match = re.search(r"\[([0-9a-fA-F:.]+)\]|(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)", by_paren)
                if ip_match:
                    by_ip = ip_match.group(1) or ip_match.group(2)

        # Extract "with <protocol>"
        with_match = re.search(r"\bwith\s+([^\s;()]+)", content_part, re.IGNORECASE)
        if with_match:
            with_proto = with_match.group(1).strip()

        # Extract "id <msgid>"
        id_match = re.search(r"\bid\s+([^\s;()]+)", content_part, re.IGNORECASE)
        if id_match:
            msg_id = id_match.group(1).strip()

        # Extract "for <recipient>"
        for_match = re.search(r"\bfor\s+<([^>]+)>|\bfor\s+([^\s;()]+)", content_part, re.IGNORECASE)
        if for_match:
            for_recip = (for_match.group(1) or for_match.group(2)).strip()

        # Extract TLS details if present in header
        tls_match = re.search(
            r"(version=(?:TLSv?[0-9_.]+)|cipher=[^\s;()]+|using\s+TLS[^\s;()]*|\(using\s+TLS[^\)]*\))",
            content_part,
            re.IGNORECASE
        )
        if tls_match:
            tls_cipher = tls_match.group(0).strip("()")

        # Tri-State Transport Security Determination
        proto_upper = with_proto.upper() if with_proto else ""
        if bool(tls_match) or any(proto_upper.startswith(k) for k in ["ESMTPS", "SMTPS", "HTTPS", "TLS"]):
            transport_sec = "ENCRYPTED_ASSERTED"
            is_tls = True
        elif proto_upper in ["SMTP", "ESMTP", "HTTP"]:
            transport_sec = "PLAINTEXT_ASSERTED"
            is_tls = False
        else:
            transport_sec = "UNKNOWN"
            is_tls = None

        # Determine parse quality
        if not from_host and not by_host and not ts_raw:
            status = "MALFORMED"
        elif not from_host or not by_host:
            status = "PARTIAL"
        else:
            status = "PARSED"

        return RelayHop(
            hop_index=index,
            raw_header=clean_rcvd,
            from_host=from_host,
            from_ip=from_ip,
            by_host=by_host,
            by_ip=by_ip,
            with_protocol=with_proto,
            id=msg_id,
            for_recipient=for_recip,
            tls_cipher=tls_cipher,
            transport_security_status=transport_sec,
            is_tls_encrypted=is_tls,
            timestamp_raw=ts_raw,
            timestamp_iso=ts_iso,
            evidence_nature="ASSERTED_HEADER_EVIDENCE",
            parse_status=status
        )

    @staticmethod
    def parse_auth_results_header(raw_header: str) -> AssertedAuthResult:
        """Parses an RFC 7601 / RFC 8601 Authentication-Results header."""
        clean_ar = " ".join(raw_header.split())
        authserv = None
        if ";" in clean_ar:
            authserv = clean_ar.split(";", 1)[0].strip()
        else:
            authserv = clean_ar.split()[0] if clean_ar.split() else None

        spf_res = None
        spf_mailfrom = None
        spf_reason = None
        dkim_res = None
        dkim_domain = None
        dkim_selector = None
        dkim_reason = None
        dmarc_res = None
        dmarc_from = None
        dmarc_reason = None
        arc_res = None

        # Parse SPF
        spf_m = re.search(r"\bspf=([a-zA-Z0-9_-]+)(?:\s*\([^)]*\))?", clean_ar, re.IGNORECASE)
        if spf_m:
            spf_res = spf_m.group(1).lower()
        mf_m = re.search(r"smtp\.mailfrom=([^\s;()]+)", clean_ar, re.IGNORECASE)
        if mf_m:
            spf_mailfrom = mf_m.group(1).strip()
        spf_r = re.search(r"\bspf=[^;]+\breason=([^\s;()]+)", clean_ar, re.IGNORECASE)
        if spf_r:
            spf_reason = spf_r.group(1).strip()

        # Parse DKIM
        dkim_m = re.search(r"\bdkim=([a-zA-Z0-9_-]+)(?:\s*\([^)]*\))?", clean_ar, re.IGNORECASE)
        if dkim_m:
            dkim_res = dkim_m.group(1).lower()
        hd_m = re.search(r"header\.d=([^\s;()]+)", clean_ar, re.IGNORECASE)
        if hd_m:
            dkim_domain = hd_m.group(1).strip()
        hs_m = re.search(r"header\.s=([^\s;()]+)", clean_ar, re.IGNORECASE)
        if hs_m:
            dkim_selector = hs_m.group(1).strip()
        dkim_r = re.search(r"\bdkim=[^;]+\breason=([^\s;()]+)", clean_ar, re.IGNORECASE)
        if dkim_r:
            dkim_reason = dkim_r.group(1).strip()

        # Parse DMARC
        dmarc_m = re.search(r"\bdmarc=([a-zA-Z0-9_-]+)(?:\s*\([^)]*\))?", clean_ar, re.IGNORECASE)
        if dmarc_m:
            dmarc_res = dmarc_m.group(1).lower()
        hf_m = re.search(r"header\.from=([^\s;()]+)", clean_ar, re.IGNORECASE)
        if hf_m:
            dmarc_from = hf_m.group(1).strip()
        dmarc_r = re.search(r"\bdmarc=[^;]+\breason=([^\s;()]+)", clean_ar, re.IGNORECASE)
        if dmarc_r:
            dmarc_reason = dmarc_r.group(1).strip()

        # Parse ARC
        arc_m = re.search(r"\barc=([a-zA-Z0-9_-]+)", clean_ar, re.IGNORECASE)
        if arc_m:
            arc_res = arc_m.group(1).lower()

        return AssertedAuthResult(
            authserv_id=authserv,
            raw_header=clean_ar,
            spf_result=spf_res,
            spf_mailfrom=spf_mailfrom,
            spf_reason=spf_reason,
            dkim_result=dkim_res,
            dkim_domain=dkim_domain,
            dkim_selector=dkim_selector,
            dkim_reason=dkim_reason,
            dmarc_result=dmarc_res,
            dmarc_from=dmarc_from,
            dmarc_reason=dmarc_reason,
            arc_result=arc_res,
            evidence_nature="ASSERTED_AUTH_RESULT",
            independent_verification_status="NOT_VERIFIED"
        )

    @staticmethod
    def parse_received_spf_header(raw_header: str) -> AssertedReceivedSPF:
        """Parses an RFC 7208 Received-SPF header."""
        clean_spf = " ".join(raw_header.split())
        res_m = re.search(r"^([a-zA-Z0-9_-]+)", clean_spf)
        res_val = res_m.group(1).lower() if res_m else None

        ip_m = re.search(r"client-ip=([0-9a-fA-F:.]+)", clean_spf, re.IGNORECASE)
        client_ip = ip_m.group(1) if ip_m else None

        env_m = re.search(r"envelope-from=([^\s;()]+)", clean_spf, re.IGNORECASE)
        env_from = env_m.group(1) if env_m else None

        rcv_m = re.search(r"receiver=([^\s;()]+)", clean_spf, re.IGNORECASE)
        receiver = rcv_m.group(1) if rcv_m else None

        id_m = re.search(r"identity=([^\s;()]+)", clean_spf, re.IGNORECASE)
        identity = id_m.group(1) if id_m else None

        mech_m = re.search(r"mechanism=([^\s;()]+)", clean_spf, re.IGNORECASE)
        mechanism = mech_m.group(1) if mech_m else None

        return AssertedReceivedSPF(
            result=res_val,
            client_ip=client_ip,
            envelope_from=env_from,
            receiver=receiver,
            identity=identity,
            mechanism=mechanism,
            raw_header=clean_spf,
            evidence_nature="ASSERTED_SPF_RESULT"
        )

    @staticmethod
    def parse_dkim_signature_header(raw_header: str) -> DKIMSignatureMetadata:
        """Parses a DKIM-Signature header per RFC 6376 without executing cryptographic verification."""
        clean_sig = " ".join(raw_header.split())
        tags: Dict[str, str] = {}
        for part in clean_sig.split(";"):
            part_clean = part.strip()
            if "=" in part_clean:
                k, v = part_clean.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        return DKIMSignatureMetadata(
            v=tags.get("v"),
            a=tags.get("a"),
            d=tags.get("d"),
            s=tags.get("s"),
            c=tags.get("c"),
            q=tags.get("q"),
            h=tags.get("h"),
            bh=tags.get("bh"),
            b=tags.get("b"),
            t=tags.get("t"),
            x=tags.get("x"),
            raw_header=clean_sig,
            dkim_verification_status="NOT_VERIFIED",
            evidence_nature="ASSERTED_SIGNATURE_METADATA"
        )

    @classmethod
    def evaluate_relationships(
        cls,
        from_hdr: Optional[EMLAddressHeader],
        sender_hdr: Optional[EMLAddressHeader],
        reply_to_hdr: Optional[EMLAddressHeader],
        return_path_hdr: Optional[EMLAddressHeader],
        message_id: Optional[str]
    ) -> List[HeaderRelationship]:
        """
        Evaluates domain consistency across RFC headers without fabricating phishing or spoofing claims.
        Uses neutral wording ('matches' or 'different').
        """
        relationships: List[HeaderRelationship] = []

        # 1. From vs Return-Path
        if from_hdr and return_path_hdr and from_hdr.domain and return_path_hdr.domain:
            f_dom = from_hdr.domain
            r_dom = return_path_hdr.domain
            if f_dom == r_dom or r_dom.endswith(f".{f_dom}") or f_dom.endswith(f".{r_dom}"):
                rel_status = "MATCH"
                desc = f"From domain matches Return-Path domain (@{f_dom})."
            else:
                rel_status = "DIFFERENT"
                desc = f"Header domains differ: From (@{f_dom}) vs Return-Path (@{r_dom}). Common in multi-tenant relaying, mailing lists, or forwarding."
            relationships.append(HeaderRelationship(
                comparison="FROM_VS_RETURN_PATH",
                header_a_name="From",
                header_a_value=from_hdr.address,
                header_a_domain=f_dom,
                header_b_name="Return-Path",
                header_b_value=return_path_hdr.address,
                header_b_domain=r_dom,
                status=rel_status,
                description=desc
            ))
        elif from_hdr and from_hdr.domain:
            relationships.append(HeaderRelationship(
                comparison="FROM_VS_RETURN_PATH",
                header_a_name="From",
                header_a_value=from_hdr.address,
                header_a_domain=from_hdr.domain,
                header_b_name="Return-Path",
                header_b_value=None,
                header_b_domain=None,
                status="NOT_PRESENT",
                description="Return-Path header not present in message."
            ))

        # 2. From vs Sender
        if from_hdr and sender_hdr and from_hdr.domain and sender_hdr.domain:
            f_dom = from_hdr.domain
            s_dom = sender_hdr.domain
            if f_dom == s_dom or s_dom.endswith(f".{f_dom}") or f_dom.endswith(f".{s_dom}"):
                rel_status = "MATCH"
                desc = f"From domain matches Sender domain (@{s_dom})."
            else:
                rel_status = "DIFFERENT"
                desc = f"Header domains differ: From (@{f_dom}) vs Sender (@{s_dom}). Common when sending on behalf of another entity (RFC 5322 Section 3.6.2)."
            relationships.append(HeaderRelationship(
                comparison="FROM_VS_SENDER",
                header_a_name="From",
                header_a_value=from_hdr.address,
                header_a_domain=f_dom,
                header_b_name="Sender",
                header_b_value=sender_hdr.address,
                header_b_domain=s_dom,
                status=rel_status,
                description=desc
            ))

        # 3. Reply-To vs From
        if from_hdr and reply_to_hdr and from_hdr.domain and reply_to_hdr.domain:
            f_dom = from_hdr.domain
            rt_dom = reply_to_hdr.domain
            if f_dom == rt_dom or rt_dom.endswith(f".{f_dom}") or f_dom.endswith(f".{rt_dom}"):
                rel_status = "MATCH"
                desc = f"Reply-To domain matches From domain (@{f_dom})."
            else:
                rel_status = "DIFFERENT"
                desc = f"Header domains differ: Reply-To (@{rt_dom}) vs From (@{f_dom}). Standard in helpdesk ticketing, mailing lists, and outsourced campaigns."
            relationships.append(HeaderRelationship(
                comparison="REPLY_TO_VS_FROM",
                header_a_name="Reply-To",
                header_a_value=reply_to_hdr.address,
                header_a_domain=rt_dom,
                header_b_name="From",
                header_b_value=from_hdr.address,
                header_b_domain=f_dom,
                status=rel_status,
                description=desc
            ))

        # 4. Message-ID domain vs From domain
        if from_hdr and from_hdr.domain and message_id:
            msg_id_clean = message_id.strip("<> \t\r\n")
            msg_id_domain = None
            if "@" in msg_id_clean:
                msg_id_domain = msg_id_clean.split("@", 1)[1].lower().strip()

            if msg_id_domain:
                f_dom = from_hdr.domain
                if f_dom == msg_id_domain or msg_id_domain.endswith(f".{f_dom}") or f_dom.endswith(f".{msg_id_domain}"):
                    rel_status = "MATCH"
                    desc = f"Message-ID domain matches From domain (@{f_dom})."
                else:
                    rel_status = "DIFFERENT"
                    desc = f"Header domains differ: Message-ID (@{msg_id_domain}) vs From (@{f_dom}). Typical when messages are generated by third-party mail gateways."
                relationships.append(HeaderRelationship(
                    comparison="MESSAGE_ID_VS_FROM",
                    header_a_name="Message-ID",
                    header_a_value=message_id,
                    header_a_domain=msg_id_domain,
                    header_b_name="From",
                    header_b_value=from_hdr.address,
                    header_b_domain=f_dom,
                    status=rel_status,
                    description=desc
                ))

        return relationships
