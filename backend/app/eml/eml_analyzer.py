"""
SecureMailScope X - RFC 5322 .EML Message & Email Header Forensic Analyzer (Phase 8)
Extracts structured relay chains, asserted authentication headers, DKIM signature metadata,
MIME attachments with SHA-256 hashes of decoded bytes, and non-speculative header relationships.

Forensic Rules & Provenance:
1. Parse strictly what is present in the message; never fabricate missing headers, hops, or IPs.
2. Received headers are untrusted message metadata (ASSERTED_HEADER_EVIDENCE).
3. Authentication-Results are treated as asserted header evidence, not verified telemetry.
4. DKIM-Signature presence leaves dkim_verification_status = "NOT_VERIFIED" without cryptographic proof.
5. Header domain mismatches produce neutral comparison findings ("Header domains differ"),
   NEVER speculative claims like "phishing", "spoofing", or "malicious".
6. Attachments are parsed for metadata and hashed; never executed or labeled malware.
7. Provenance is strictly source = "EML_HEADER".
"""

import email
from email import policy
import hashlib
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from app.eml.header_forensics import (
    HeaderForensics,
    RelayHop,
    HeaderRelationship,
    AssertedAuthResult,
    AssertedReceivedSPF,
    DKIMSignatureMetadata,
    AttachmentMetadata,
    EMLBodySummary,
    EMLDateMetadata,
    EMLAddressHeader
)


@dataclass
class EMLForensicReport:
    """Structured, evidence-bounded forensic analysis of an RFC 5322 .EML message."""
    source: str = "EML_HEADER"
    message_id: Optional[str] = None
    message_id_domain: Optional[str] = None
    date: EMLDateMetadata = field(default_factory=EMLDateMetadata)
    subject: Optional[str] = None
    from_header: Optional[EMLAddressHeader] = None
    sender_header: Optional[EMLAddressHeader] = None
    reply_to_header: Optional[EMLAddressHeader] = None
    return_path_header: Optional[EMLAddressHeader] = None
    to_headers: List[str] = field(default_factory=list)
    cc_headers: List[str] = field(default_factory=list)
    received_headers_raw: List[str] = field(default_factory=list)
    relay_chain: List[RelayHop] = field(default_factory=list)
    header_relationships: List[HeaderRelationship] = field(default_factory=list)
    authentication_results: List[AssertedAuthResult] = field(default_factory=list)
    received_spf: List[AssertedReceivedSPF] = field(default_factory=list)
    dkim_signatures: List[DKIMSignatureMetadata] = field(default_factory=list)
    mime_content_type: str = "text/plain"
    attachments: List[AttachmentMetadata] = field(default_factory=list)
    body_summary: EMLBodySummary = field(default_factory=EMLBodySummary)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    analysis_limitations: List[str] = field(default_factory=list)

    # Legacy convenience accessors for backwards compatibility
    @property
    def total_hops(self) -> int:
        return len(self.relay_chain)

    @property
    def hops(self) -> List[RelayHop]:
        return self.relay_chain

    @property
    def has_insecure_hop(self) -> bool:
        return any(h.transport_security_status == "PLAINTEXT_ASSERTED" for h in self.relay_chain)

    @property
    def dmarc_auth_result(self) -> Optional[str]:
        for ar in self.authentication_results:
            if ar.dmarc_result:
                return ar.dmarc_result
        return None

    @property
    def spf_auth_result(self) -> Optional[str]:
        for ar in self.authentication_results:
            if ar.spf_result:
                return ar.spf_result
        return None

    @property
    def dkim_auth_result(self) -> Optional[str]:
        for ar in self.authentication_results:
            if ar.dkim_result:
                return ar.dkim_result
        return None

    @property
    def inconsistencies(self) -> List[str]:
        return [r.description for r in self.header_relationships if r.status == "DIFFERENT"]

    def to_dict(self) -> Dict[str, Any]:
        """Serializes report into JSON-compatible dictionary."""
        return {
            "source": self.source,
            "message_id": self.message_id,
            "message_id_domain": self.message_id_domain,
            "date": self.date.__dict__,
            "subject": self.subject,
            "from_header": self.from_header.__dict__ if self.from_header else None,
            "sender_header": self.sender_header.__dict__ if self.sender_header else None,
            "reply_to_header": self.reply_to_header.__dict__ if self.reply_to_header else None,
            "return_path_header": self.return_path_header.__dict__ if self.return_path_header else None,
            "to_headers": self.to_headers,
            "cc_headers": self.cc_headers,
            "received_headers_raw": self.received_headers_raw,
            "relay_chain": [h.__dict__ for h in self.relay_chain],
            "header_relationships": [r.__dict__ for r in self.header_relationships],
            "authentication_results": [a.__dict__ for a in self.authentication_results],
            "received_spf": [s.__dict__ for s in self.received_spf],
            "dkim_signatures": [d.__dict__ for d in self.dkim_signatures],
            "mime_content_type": self.mime_content_type,
            "attachments": [att.__dict__ for att in self.attachments],
            "body_summary": self.body_summary.__dict__,
            "findings": self.findings,
            "analysis_limitations": self.analysis_limitations,
            # Legacy compatibility fields
            "total_hops": self.total_hops,
            "hops": [h.__dict__ for h in self.relay_chain],
            "from_hdr": self.from_header.raw_value if self.from_header else None,
            "return_path": self.return_path_header.raw_value if self.return_path_header else None,
            "date_header_iso": self.date.timestamp_iso
        }


class EMLForensicAnalyzer:
    """Performs static forensic inspection of RFC email messages and header chains."""

    @classmethod
    def parse_eml_content(cls, eml_bytes_or_str: Any) -> EMLForensicReport:
        """
        Parses raw .EML bytes or RFC 5322 string into a structured EMLForensicReport.
        Preserves original header ordering and extracts verified metadata only.
        """
        if isinstance(eml_bytes_or_str, bytes):
            msg = email.message_from_bytes(eml_bytes_or_str, policy=policy.default)
        else:
            msg = email.message_from_string(str(eml_bytes_or_str), policy=policy.default)

        # 1. Identity and Address Headers
        message_id = msg.get("Message-ID")
        msg_id_domain = None
        if message_id:
            clean_mid = message_id.strip("<> \t\r\n")
            if "@" in clean_mid:
                msg_id_domain = clean_mid.split("@", 1)[1].lower().strip()

        from_hdr = HeaderForensics.parse_address_header(msg.get("From"))
        sender_hdr = HeaderForensics.parse_address_header(msg.get("Sender"))
        reply_to_hdr = HeaderForensics.parse_address_header(msg.get("Reply-To"))
        return_path_hdr = HeaderForensics.parse_address_header(msg.get("Return-Path"))
        subject = msg.get("Subject")
        date_meta = HeaderForensics.parse_date_header(msg.get("Date"))

        # Recipient lists (preserving raw entries)
        to_list = [str(t).strip() for t in msg.get_all("To", []) if str(t).strip()]
        cc_list = [str(c).strip() for c in msg.get_all("Cc", []) if str(c).strip()]

        # 2. Received Headers & Relay Chain (Preserve original appearance order top-to-bottom)
        raw_received_headers = [str(r) for r in msg.get_all("Received", [])]
        relay_chain: List[RelayHop] = []
        has_plaintext_hop = False

        for idx, raw_rcvd in enumerate(raw_received_headers, 1):
            hop = HeaderForensics.parse_received_hop(raw_rcvd, idx)
            relay_chain.append(hop)
            if hop.transport_security_status == "PLAINTEXT_ASSERTED":
                has_plaintext_hop = True

        # 3. Authentication-Results Headers (RFC 7601 / 8601)
        raw_auth_results = [str(a) for a in msg.get_all("Authentication-Results", [])]
        auth_results_parsed = [
            HeaderForensics.parse_auth_results_header(a) for a in raw_auth_results
        ]

        # 4. Received-SPF Headers (RFC 7208)
        raw_received_spf = [str(s) for s in msg.get_all("Received-SPF", [])]
        received_spf_parsed = [
            HeaderForensics.parse_received_spf_header(s) for s in raw_received_spf
        ]

        # 5. DKIM-Signature Headers (RFC 6376)
        raw_dkim_signatures = [str(d) for d in msg.get_all("DKIM-Signature", [])]
        dkim_signatures_parsed = [
            HeaderForensics.parse_dkim_signature_header(d) for d in raw_dkim_signatures
        ]

        # 6. Header Relationships
        relationships = HeaderForensics.evaluate_relationships(
            from_hdr=from_hdr,
            sender_hdr=sender_hdr,
            reply_to_hdr=reply_to_hdr,
            return_path_hdr=return_path_hdr,
            message_id=message_id
        )

        # 7. MIME & Attachment Inspection
        top_mime_type = msg.get_content_type() or "text/plain"
        attachments: List[AttachmentMetadata] = []
        has_text_plain = False
        has_text_html = False
        total_body_bytes = 0

        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get("Content-Disposition", ""))
            fname = part.get_filename()
            is_attachment = ("attachment" in cdisp.lower()) or bool(fname)

            if is_attachment:
                # Extract decoded payload safely without executing
                try:
                    payload = part.get_payload(decode=True)
                    payload_bytes = payload if isinstance(payload, bytes) else b""
                except Exception:
                    payload_bytes = b""

                sha256_hash = hashlib.sha256(payload_bytes).hexdigest() if payload_bytes else None
                t_encoding = part.get("Content-Transfer-Encoding")

                attachments.append(AttachmentMetadata(
                    filename=fname,
                    content_type=ctype,
                    content_disposition=cdisp if cdisp else None,
                    transfer_encoding=str(t_encoding) if t_encoding else None,
                    size_bytes=len(payload_bytes),
                    attachment_sha256=sha256_hash,
                    hash_source="DECODED_ATTACHMENT_BYTES"
                ))
            else:
                if ctype == "text/plain":
                    has_text_plain = True
                elif ctype == "text/html":
                    has_text_html = True

                try:
                    p = part.get_payload(decode=True)
                    if p and isinstance(p, bytes):
                        total_body_bytes += len(p)
                except Exception:
                    pass

        body_summary = EMLBodySummary(
            has_text_plain=has_text_plain,
            has_text_html=has_text_html,
            mime_structure=top_mime_type,
            total_body_bytes=total_body_bytes,
            attachment_count=len(attachments)
        )

        # 8. Evidence-Bounded Findings Generation
        findings: List[Dict[str, Any]] = []
        limitations: List[str] = [
            "EML header evidence is asserted by transmitting/receiving MTAs and is not corroborated with live network telemetry.",
            "DKIM signatures observed in headers remain NOT_VERIFIED without independent cryptographic verification."
        ]

        # Relationship findings
        for rel in relationships:
            if rel.comparison == "FROM_VS_RETURN_PATH" and rel.status == "DIFFERENT":
                findings.append({
                    "id": "FINDING-EML-HEADER-FROM-RETURN-PATH-DIFFER",
                    "title": "Header From and Return-Path Domains Differ",
                    "severity": "LOW",
                    "category": "DOMAIN_AUTHENTICATION",
                    "description": rel.description,
                    "evidence_nature": "ASSERTED_HEADER_EVIDENCE"
                })
            elif rel.comparison == "REPLY_TO_VS_FROM" and rel.status == "DIFFERENT":
                findings.append({
                    "id": "FINDING-EML-HEADER-REPLY-TO-FROM-DIFFER",
                    "title": "Reply-To and From Domains Differ",
                    "severity": "INFO",
                    "category": "DOMAIN_AUTHENTICATION",
                    "description": rel.description,
                    "evidence_nature": "ASSERTED_HEADER_EVIDENCE"
                })

        # Multiple Authentication-Results
        if len(auth_results_parsed) > 1:
            findings.append({
                "id": "FINDING-EML-MULTIPLE-AUTH-RESULTS",
                "title": "Multiple Authentication-Results Headers Observed",
                "severity": "INFO",
                "category": "DOMAIN_AUTHENTICATION",
                "description": f"Message contains {len(auth_results_parsed)} separate Authentication-Results headers from different hops/relays.",
                "evidence_nature": "ASSERTED_AUTH_RESULT"
            })

        # Malformed Date
        if date_meta.parse_status == "MALFORMED":
            findings.append({
                "id": "FINDING-EML-MALFORMED-DATE",
                "title": "Malformed Date Header Format",
                "severity": "LOW",
                "category": "MESSAGE_STRUCTURE",
                "description": f"Date header '{date_meta.raw_value}' violates RFC 5322 date-time syntax.",
                "evidence_nature": "ASSERTED_HEADER_EVIDENCE"
            })

        # Malformed Received Hop
        malformed_hops = [h for h in relay_chain if h.parse_status == "MALFORMED"]
        if malformed_hops:
            findings.append({
                "id": "FINDING-EML-MALFORMED-RECEIVED",
                "title": "Malformed Received Header Format",
                "severity": "LOW",
                "category": "RELAY_ROUTING",
                "description": f"One or more Received headers could not be parsed according to standard RFC 5321 syntax ({len(malformed_hops)} malformed hop(s)).",
                "evidence_nature": "ASSERTED_HEADER_EVIDENCE"
            })

        # DKIM Signatures Present
        if dkim_signatures_parsed:
            findings.append({
                "id": "FINDING-EML-DKIM-SIGNATURE-NOT-VERIFIED",
                "title": "DKIM Signature Observed (Cryptographically Unverified)",
                "severity": "INFO",
                "category": "CRYPTOGRAPHIC_STRENGTH",
                "description": f"Message contains {len(dkim_signatures_parsed)} DKIM-Signature header(s); cryptographic verification status is NOT_VERIFIED.",
                "evidence_nature": "ASSERTED_SIGNATURE_METADATA"
            })

        # Unencrypted Transit Hop (only when explicitly asserted plaintext)
        if has_plaintext_hop:
            findings.append({
                "id": "FINDING-EML-PLAINTEXT-RELAY-HOP",
                "title": "Unencrypted Email Relay Hop in Transit",
                "severity": "LOW",
                "category": "RELAY_ROUTING",
                "description": "One or more intermediary MTA hops in the Received chain explicitly asserted unencrypted plaintext transport.",
                "evidence_nature": "ASSERTED_HEADER_EVIDENCE"
            })

        return EMLForensicReport(
            source="EML_HEADER",
            message_id=message_id,
            message_id_domain=msg_id_domain,
            date=date_meta,
            subject=subject,
            from_header=from_hdr,
            sender_header=sender_hdr,
            reply_to_header=reply_to_hdr,
            return_path_header=return_path_hdr,
            to_headers=to_list,
            cc_headers=cc_list,
            received_headers_raw=raw_received_headers,
            relay_chain=relay_chain,
            header_relationships=relationships,
            authentication_results=auth_results_parsed,
            received_spf=received_spf_parsed,
            dkim_signatures=dkim_signatures_parsed,
            mime_content_type=top_mime_type,
            attachments=attachments,
            body_summary=body_summary,
            findings=findings,
            analysis_limitations=limitations
        )
