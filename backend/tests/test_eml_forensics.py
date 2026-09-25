"""
SecureMailScope X - RFC 5322 .EML Header Forensics & Relay-Chain Tests (Phase 8 & 8.5)
Deterministic verification tests covering:
1. Basic RFC 5322 parsing (headers, subject, date, message_id).
2. Multiple Received headers preserve original order.
3. Relay chain derives only observable hops without invented hops.
4. From == Return-Path -> MATCH ("matches" wording).
5. From != Return-Path -> DIFFERENT, no spoofing claim.
6. Reply-To differs from From -> difference only, no phishing claim.
7. Multiple Authentication-Results preserved independently.
8. Authentication-Results DKIM=pass -> asserted pass, independent verification remains NOT_VERIFIED.
9. DKIM-Signature metadata parsing (v, a, d, s, c, q, h, bh, b, t, x) with NOT_VERIFIED status.
10. Received-SPF parsing remains asserted evidence.
11. Malformed Date header -> parse failure captured (parse_status = MALFORMED), not invented timestamp.
12. Malformed Received header -> preserved raw header + parse_status = MALFORMED.
13. Message-ID domain parsing.
14. MIME attachment metadata extraction without executing code.
15. Attachment SHA-256 derived from actual decoded bytes (hash_source = DECODED_ATTACHMENT_BYTES).
16. EML header evidence never mutates PCAP SecurityGrade, EvidenceConfidence, PFS, PQC, or certificate findings.
17. Anti-overclaim verification: No header mismatch emits SPOOFING_CONFIRMED or PHISHING_CONFIRMED.
18. Tri-State Transport Security: ESMTPS/TLS -> ENCRYPTED_ASSERTED (is_tls_encrypted = True).
19. Tri-State Transport Security: Header without TLS/protocol marker -> UNKNOWN (is_tls_encrypted = None), no plaintext finding.
20. Tri-State Transport Security: Explicit with SMTP -> PLAINTEXT_ASSERTED (is_tls_encrypted = False), plaintext finding emitted.
21. Header comparison wording uses "matches", not "aligns".
"""

import os
import sys
import unittest
import hashlib

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.eml.header_forensics import HeaderForensics, RelayHop
from app.eml.eml_analyzer import EMLForensicAnalyzer, EMLForensicReport
from app.schemas.forensic import (
    EmailSession,
    EmailProtocol,
    SecurityMode,
    TLSHandshakeDetails,
    TLSVersion,
    CipherSuiteInfo,
    SecurityStrength,
    SecurityGrade,
    FindingCategory
)
from app.forensic.rule_engine import CryptographicRuleEngine


class TestEMLForensics(unittest.TestCase):

    def setUp(self):
        self.sample_eml = (
            "Delivered-To: recipient@example.com\r\n"
            "Received: by mail-wm1-f41.google.com with SMTP id 20231115T1000\r\n"
            "        for <recipient@example.com>; Wed, 15 Nov 2023 02:00:00 -0800 (PST)\r\n"
            "Received: from relay.corp.com (relay.corp.com. [198.51.100.25])\r\n"
            "        by mx.google.com with ESMTPS id abc123\r\n"
            "        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384);\r\n"
            "        Wed, 15 Nov 2023 01:59:50 -0800 (PST)\r\n"
            "Authentication-Results: mx.google.com;\r\n"
            "       dkim=pass header.i=@corp.com header.s=s2023;\r\n"
            "       spf=pass (google.com: domain of sender@corp.com designates 198.51.100.25 as permitted sender) smtp.mailfrom=sender@corp.com;\r\n"
            "       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=corp.com\r\n"
            "Received-SPF: pass (google.com: domain of sender@corp.com designates 198.51.100.25 as permitted sender) client-ip=198.51.100.25;\r\n"
            "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=corp.com; s=s2023;\r\n"
            "        t=1700000000; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;\r\n"
            "        h=From:To:Subject:Date:Message-ID;\r\n"
            "        b=abcdef123456...\r\n"
            "From: Corporate Sender <sender@corp.com>\r\n"
            "To: Recipient User <recipient@example.com>\r\n"
            "Subject: Q4 Security Audit Notice\r\n"
            "Date: Wed, 15 Nov 2023 09:59:00 +0000\r\n"
            "Message-ID: <audit-20231115-001@corp.com>\r\n"
            "Return-Path: <sender@corp.com>\r\n"
            "Content-Type: text/plain; charset=\"UTF-8\"\r\n"
            "\r\n"
            "This is a verified test email body.\r\n"
        )

    # -----------------------------------------------------------------------
    # TEST 1: Basic RFC 5322 parsing
    # -----------------------------------------------------------------------
    def test_01_basic_rfc5322_parsing(self):
        report = EMLForensicAnalyzer.parse_eml_content(self.sample_eml)

        self.assertEqual(report.source, "EML_HEADER")
        self.assertEqual(report.subject, "Q4 Security Audit Notice")
        self.assertEqual(report.message_id, "<audit-20231115-001@corp.com>")
        self.assertEqual(report.message_id_domain, "corp.com")
        self.assertIsNotNone(report.from_header)
        self.assertEqual(report.from_header.display_name, "Corporate Sender")
        self.assertEqual(report.from_header.address, "sender@corp.com")
        self.assertEqual(report.from_header.domain, "corp.com")
        self.assertEqual(report.date.parse_status, "VALID")
        self.assertEqual(report.date.timestamp_iso, "2023-11-15T09:59:00+00:00")
        self.assertEqual(report.body_summary.has_text_plain, True)

    # -----------------------------------------------------------------------
    # TEST 2: Multiple Received headers preserve original appearance order
    # -----------------------------------------------------------------------
    def test_02_multiple_received_headers_preserve_original_order(self):
        report = EMLForensicAnalyzer.parse_eml_content(self.sample_eml)

        self.assertEqual(len(report.received_headers_raw), 2)
        self.assertEqual(len(report.relay_chain), 2)
        # Hop 1 in original appearance order is top header (mail-wm1-f41.google.com)
        self.assertEqual(report.relay_chain[0].hop_index, 1)
        self.assertIn("mail-wm1-f41.google.com", report.relay_chain[0].raw_header)
        # Hop 2 in original appearance order is second header (relay.corp.com)
        self.assertEqual(report.relay_chain[1].hop_index, 2)
        self.assertIn("relay.corp.com", report.relay_chain[1].raw_header)

    # -----------------------------------------------------------------------
    # TEST 3: Relay chain derives only observable hops
    # -----------------------------------------------------------------------
    def test_03_relay_chain_observable_hops_only(self):
        report = EMLForensicAnalyzer.parse_eml_content(self.sample_eml)

        hop2 = report.relay_chain[1]
        self.assertEqual(hop2.from_host, "relay.corp.com")
        self.assertEqual(hop2.from_ip, "198.51.100.25")
        self.assertEqual(hop2.by_host, "mx.google.com")
        self.assertEqual(hop2.with_protocol, "ESMTPS")
        self.assertEqual(hop2.transport_security_status, "ENCRYPTED_ASSERTED")
        self.assertTrue(hop2.is_tls_encrypted)
        self.assertEqual(hop2.evidence_nature, "ASSERTED_HEADER_EVIDENCE")

    # -----------------------------------------------------------------------
    # TEST 4: From == Return-Path -> MATCH ("matches" wording)
    # -----------------------------------------------------------------------
    def test_04_from_matches_return_path(self):
        report = EMLForensicAnalyzer.parse_eml_content(self.sample_eml)

        rel = next((r for r in report.header_relationships if r.comparison == "FROM_VS_RETURN_PATH"), None)
        self.assertIsNotNone(rel)
        self.assertEqual(rel.status, "MATCH")
        self.assertEqual(rel.header_a_domain, "corp.com")
        self.assertEqual(rel.header_b_domain, "corp.com")
        self.assertIn("matches", rel.description)
        self.assertNotIn("aligns", rel.description)

    # -----------------------------------------------------------------------
    # TEST 5: From != Return-Path -> DIFFERENT, no spoofing claim
    # -----------------------------------------------------------------------
    def test_05_from_differs_from_return_path_no_spoofing_claim(self):
        eml_mismatch = (
            "From: Newsletter <news@marketing.com>\r\n"
            "Return-Path: <bounces@esp-relay.net>\r\n"
            "Subject: Monthly Update\r\n"
            "Date: Wed, 15 Nov 2023 10:00:00 +0000\r\n\r\n"
            "Hello World\r\n"
        )
        report = EMLForensicAnalyzer.parse_eml_content(eml_mismatch)

        rel = next((r for r in report.header_relationships if r.comparison == "FROM_VS_RETURN_PATH"), None)
        self.assertIsNotNone(rel)
        self.assertEqual(rel.status, "DIFFERENT")
        self.assertIn("Header domains differ", rel.description)
        # Anti-overclaim check: neutral wording
        self.assertNotIn("spoof", rel.description.lower())
        self.assertNotIn("phish", rel.description.lower())
        self.assertNotIn("malicious", rel.description.lower())

        finding = next((f for f in report.findings if f["id"] == "FINDING-EML-HEADER-FROM-RETURN-PATH-DIFFER"), None)
        self.assertIsNotNone(finding)
        self.assertEqual(finding["severity"], "LOW")

    # -----------------------------------------------------------------------
    # TEST 6: Reply-To differs from From -> difference only, no phishing claim
    # -----------------------------------------------------------------------
    def test_06_reply_to_differs_from_from_neutral_claim(self):
        eml_replyto = (
            "From: Support Team <support@company.org>\r\n"
            "Reply-To: Helpdesk Agent <ticket-1234@zendesk-gateway.com>\r\n"
            "Subject: Ticket #1234\r\n"
            "Date: Wed, 15 Nov 2023 10:00:00 +0000\r\n\r\n"
            "Ticket details...\r\n"
        )
        report = EMLForensicAnalyzer.parse_eml_content(eml_replyto)

        rel = next((r for r in report.header_relationships if r.comparison == "REPLY_TO_VS_FROM"), None)
        self.assertIsNotNone(rel)
        self.assertEqual(rel.status, "DIFFERENT")
        self.assertIn("Header domains differ", rel.description)
        self.assertNotIn("phishing", rel.description.lower())

    # -----------------------------------------------------------------------
    # TEST 7: Multiple Authentication-Results preserved independently
    # -----------------------------------------------------------------------
    def test_07_multiple_authentication_results_preserved(self):
        eml_multi_ar = (
            "Authentication-Results: mta2.internal.net; spf=pass smtp.mailfrom=sender@corp.com;\r\n"
            "Authentication-Results: mx.google.com; dkim=pass header.i=@corp.com; dmarc=pass header.from=corp.com;\r\n"
            "From: sender@corp.com\r\n"
            "Subject: Multi AR test\r\n"
            "Date: Wed, 15 Nov 2023 10:00:00 +0000\r\n\r\n"
            "Body...\r\n"
        )
        report = EMLForensicAnalyzer.parse_eml_content(eml_multi_ar)

        self.assertEqual(len(report.authentication_results), 2)
        self.assertEqual(report.authentication_results[0].authserv_id, "mta2.internal.net")
        self.assertEqual(report.authentication_results[0].spf_result, "pass")
        self.assertEqual(report.authentication_results[1].authserv_id, "mx.google.com")
        self.assertEqual(report.authentication_results[1].dkim_result, "pass")

        # Emits informative finding about multiple auth-results
        multi_finding = next((f for f in report.findings if f["id"] == "FINDING-EML-MULTIPLE-AUTH-RESULTS"), None)
        self.assertIsNotNone(multi_finding)

    # -----------------------------------------------------------------------
    # TEST 8: Authentication-Results DKIM=pass -> asserted pass, NOT_VERIFIED
    # -----------------------------------------------------------------------
    def test_08_auth_results_dkim_pass_remains_asserted(self):
        report = EMLForensicAnalyzer.parse_eml_content(self.sample_eml)

        ar = report.authentication_results[0]
        self.assertEqual(ar.dkim_result, "pass")
        self.assertEqual(ar.evidence_nature, "ASSERTED_AUTH_RESULT")
        self.assertEqual(ar.independent_verification_status, "NOT_VERIFIED")

    # -----------------------------------------------------------------------
    # TEST 9: DKIM-Signature metadata parsing with NOT_VERIFIED status
    # -----------------------------------------------------------------------
    def test_09_dkim_signature_metadata_parsing(self):
        report = EMLForensicAnalyzer.parse_eml_content(self.sample_eml)

        self.assertEqual(len(report.dkim_signatures), 1)
        sig = report.dkim_signatures[0]
        self.assertEqual(sig.v, "1")
        self.assertEqual(sig.a, "rsa-sha256")
        self.assertEqual(sig.d, "corp.com")
        self.assertEqual(sig.s, "s2023")
        self.assertEqual(sig.c, "relaxed/relaxed")
        self.assertEqual(sig.bh, "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
        self.assertEqual(sig.dkim_verification_status, "NOT_VERIFIED")
        self.assertEqual(sig.evidence_nature, "ASSERTED_SIGNATURE_METADATA")

    # -----------------------------------------------------------------------
    # TEST 10: Received-SPF parsing remains asserted evidence
    # -----------------------------------------------------------------------
    def test_10_received_spf_parsing(self):
        report = EMLForensicAnalyzer.parse_eml_content(self.sample_eml)

        self.assertEqual(len(report.received_spf), 1)
        spf = report.received_spf[0]
        self.assertEqual(spf.result, "pass")
        self.assertEqual(spf.client_ip, "198.51.100.25")
        self.assertEqual(spf.evidence_nature, "ASSERTED_SPF_RESULT")

    # -----------------------------------------------------------------------
    # TEST 11: Malformed Date header -> parse_status = MALFORMED
    # -----------------------------------------------------------------------
    def test_11_malformed_date_header_captured(self):
        eml_bad_date = (
            "From: sender@corp.com\r\n"
            "Subject: Bad Date\r\n"
            "Date: NOT_A_VALID_RFC_DATE_STRING\r\n\r\n"
            "Body...\r\n"
        )
        report = EMLForensicAnalyzer.parse_eml_content(eml_bad_date)

        self.assertEqual(report.date.parse_status, "MALFORMED")
        self.assertEqual(report.date.raw_value, "NOT_A_VALID_RFC_DATE_STRING")
        self.assertIsNone(report.date.timestamp_iso)

        date_finding = next((f for f in report.findings if f["id"] == "FINDING-EML-MALFORMED-DATE"), None)
        self.assertIsNotNone(date_finding)

    # -----------------------------------------------------------------------
    # TEST 12: Malformed Received header -> parse_status = MALFORMED
    # -----------------------------------------------------------------------
    def test_12_malformed_received_header_captured(self):
        eml_bad_rcvd = (
            "Received: corrupt garbage header without standard tokens\r\n"
            "From: sender@corp.com\r\n"
            "Subject: Corrupt Hop\r\n\r\n"
            "Body...\r\n"
        )
        report = EMLForensicAnalyzer.parse_eml_content(eml_bad_rcvd)

        self.assertEqual(len(report.relay_chain), 1)
        self.assertEqual(report.relay_chain[0].parse_status, "MALFORMED")
        self.assertEqual(report.relay_chain[0].raw_header, "corrupt garbage header without standard tokens")

        rcvd_finding = next((f for f in report.findings if f["id"] == "FINDING-EML-MALFORMED-RECEIVED"), None)
        self.assertIsNotNone(rcvd_finding)

    # -----------------------------------------------------------------------
    # TEST 13: Message-ID domain parsing
    # -----------------------------------------------------------------------
    def test_13_message_id_domain_parsing(self):
        report = EMLForensicAnalyzer.parse_eml_content(self.sample_eml)

        self.assertEqual(report.message_id, "<audit-20231115-001@corp.com>")
        self.assertEqual(report.message_id_domain, "corp.com")

        rel = next((r for r in report.header_relationships if r.comparison == "MESSAGE_ID_VS_FROM"), None)
        self.assertIsNotNone(rel)
        self.assertEqual(rel.status, "MATCH")

    # -----------------------------------------------------------------------
    # TEST 14: MIME attachment metadata extraction
    # -----------------------------------------------------------------------
    def test_14_mime_attachment_metadata_extraction(self):
        eml_with_attach = (
            "From: user@corp.com\r\n"
            "Subject: Attachment Test\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/mixed; boundary=\"BOUNDARY_12345\"\r\n\r\n"
            "--BOUNDARY_12345\r\n"
            "Content-Type: text/plain; charset=\"UTF-8\"\r\n\r\n"
            "Please review attached file.\r\n"
            "--BOUNDARY_12345\r\n"
            "Content-Type: application/pdf; name=\"report.pdf\"\r\n"
            "Content-Disposition: attachment; filename=\"report.pdf\"\r\n"
            "Content-Transfer-Encoding: base64\r\n\r\n"
            "JVBERi0xLjQKJcTl8uXrp/Og0MTGCjQgMCBvYmoKPDwKL0ZpbHRlciAvRmxhdGVEZWNvZGUKL0xl\r\n"
            "--BOUNDARY_12345--\r\n"
        )
        report = EMLForensicAnalyzer.parse_eml_content(eml_with_attach)

        self.assertEqual(len(report.attachments), 1)
        att = report.attachments[0]
        self.assertEqual(att.filename, "report.pdf")
        self.assertEqual(att.content_type, "application/pdf")
        self.assertEqual(att.transfer_encoding, "base64")
        self.assertTrue(att.size_bytes > 0)
        self.assertIsNotNone(att.attachment_sha256)
        self.assertEqual(att.hash_source, "DECODED_ATTACHMENT_BYTES")

    # -----------------------------------------------------------------------
    # TEST 15: Attachment SHA-256 derived from actual decoded bytes
    # -----------------------------------------------------------------------
    def test_15_attachment_sha256_exact_hash(self):
        raw_text = "Secret Payload Content for Hash Verification"
        import base64
        b64_text = base64.b64encode(raw_text.encode("utf-8")).decode("ascii")
        expected_sha256 = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

        eml_doc = (
            "From: user@corp.com\r\n"
            "Subject: Hash Check\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/mixed; boundary=\"BND\"\r\n\r\n"
            "--BND\r\n"
            "Content-Type: text/plain; name=\"secret.txt\"\r\n"
            "Content-Disposition: attachment; filename=\"secret.txt\"\r\n"
            "Content-Transfer-Encoding: base64\r\n\r\n"
            f"{b64_text}\r\n"
            "--BND--\r\n"
        )
        report = EMLForensicAnalyzer.parse_eml_content(eml_doc)

        self.assertEqual(len(report.attachments), 1)
        self.assertEqual(report.attachments[0].attachment_sha256, expected_sha256)

    # -----------------------------------------------------------------------
    # TEST 16: EML header evidence never mutates PCAP SecurityGrade
    # -----------------------------------------------------------------------
    def test_16_eml_header_evidence_never_mutates_pcap_security_grade(self):
        # Create sample TLS 1.3 session from PCAP
        tls = TLSHandshakeDetails(
            negotiated_tls_version=TLSVersion.TLSv1_3,
            selected_cipher_code="0x1301",
            selected_cipher_name="TLS_AES_128_GCM_SHA256",
            cipher_info=CipherSuiteInfo(
                hex_code="0x1301", name="TLS_AES_128_GCM_SHA256",
                key_exchange="ECDHE", encryption="AES-128-GCM",
                hash_algorithm="SHA256", strength=SecurityStrength.STATE_OF_THE_ART,
                has_pfs=True
            ),
            has_forward_secrecy=True,
            pfs_status="Ephemeral key exchange (TLS 1.3)",
            client_hello_frame=1,
            server_hello_frame=2
        )
        session = EmailSession(
            session_id="stream_eml_pcap_test",
            stream_index=0,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.DIRECT_TLS,
            client_ip="192.168.1.100",
            client_port=45000,
            server_ip="192.0.2.25",
            server_port=465,
            server_hostname="mail.corp.com",
            start_time_epoch=1700000000.0,
            tls_details=tls
        )

        assess_pcap = CryptographicRuleEngine.evaluate_session(session)
        pcap_grade = assess_pcap.grade

        # Evaluating an EML with plaintext hops / mismatches does NOT mutate PCAP session grade
        eml_unencrypted = (
            "Received: from clear.mta (clear.mta [1.2.3.4]) by mx.dest.com with SMTP id 1;\r\n"
            "From: bad@evil.com\r\n"
            "Return-Path: <other@diff.com>\r\n"
            "Subject: Insecure transit\r\n\r\n"
            "Body\r\n"
        )
        eml_report = EMLForensicAnalyzer.parse_eml_content(eml_unencrypted)
        self.assertTrue(len(eml_report.findings) > 0)

        # Re-evaluate PCAP session -> Grade must remain strictly Grade A
        assess_pcap_recheck = CryptographicRuleEngine.evaluate_session(session)
        self.assertEqual(assess_pcap_recheck.grade, pcap_grade)
        self.assertEqual(assess_pcap_recheck.grade, SecurityGrade.A)

    # -----------------------------------------------------------------------
    # TEST 17: Anti-overclaim verification
    # -----------------------------------------------------------------------
    def test_17_anti_overclaim_safeguards(self):
        # Feed heavily mismatched headers
        eml_heavy_mismatch = (
            "From: CEO <ceo@target-bank.com>\r\n"
            "Sender: Mailer <mailer@bulk-relay.biz>\r\n"
            "Reply-To: Collector <drop@attacker-box.ru>\r\n"
            "Return-Path: <bounce@campaign-blast.io>\r\n"
            "Message-ID: <12345@unrelated-gateway.org>\r\n"
            "Subject: Urgent Wire Request\r\n\r\n"
            "Please wire funds.\r\n"
        )
        report = EMLForensicAnalyzer.parse_eml_content(eml_heavy_mismatch)

        for finding in report.findings:
            title_lower = finding["title"].lower()
            desc_lower = finding["description"].lower()
            self.assertNotIn("phishing_confirmed", title_lower)
            self.assertNotIn("spoofing_confirmed", title_lower)
            self.assertNotIn("malicious_sender", title_lower)
            self.assertNotIn("confirmed phishing", desc_lower)
            self.assertNotIn("confirmed spoofing", desc_lower)

    # -----------------------------------------------------------------------
    # TEST 18: Tri-State Transport Security: ESMTPS -> ENCRYPTED_ASSERTED
    # -----------------------------------------------------------------------
    def test_18_tri_state_transport_security_encrypted(self):
        hop = HeaderForensics.parse_received_hop(
            "from mail.corp.com (mail.corp.com [1.2.3.4]) by mx.google.com with ESMTPS id abc; Wed, 15 Nov 2023 10:00:00 +0000",
            index=1
        )
        self.assertEqual(hop.transport_security_status, "ENCRYPTED_ASSERTED")
        self.assertEqual(hop.is_tls_encrypted, True)

    # -----------------------------------------------------------------------
    # TEST 19: Tri-State Transport Security: No TLS marker -> UNKNOWN (NOT plaintext)
    # -----------------------------------------------------------------------
    def test_19_tri_state_transport_security_unknown_no_plaintext_finding(self):
        # Header without 'with' or TLS marker (e.g. local queue handoff)
        eml_unknown_hop = (
            "Received: by mail.example.com for <recipient@example.com>; Wed, 15 Nov 2023 10:00:00 +0000\r\n"
            "From: sender@example.com\r\n"
            "Subject: Unknown Transport\r\n\r\n"
            "Body\r\n"
        )
        report = EMLForensicAnalyzer.parse_eml_content(eml_unknown_hop)

        self.assertEqual(len(report.relay_chain), 1)
        hop = report.relay_chain[0]
        self.assertEqual(hop.transport_security_status, "UNKNOWN")
        self.assertIsNone(hop.is_tls_encrypted)
        self.assertFalse(report.has_insecure_hop)

        # UNKNOWN transport must NOT trigger FINDING-EML-PLAINTEXT-RELAY-HOP
        pt_finding = next((f for f in report.findings if f["id"] == "FINDING-EML-PLAINTEXT-RELAY-HOP"), None)
        self.assertIsNone(pt_finding)

    # -----------------------------------------------------------------------
    # TEST 20: Tri-State Transport Security: Explicit with SMTP -> PLAINTEXT_ASSERTED
    # -----------------------------------------------------------------------
    def test_20_tri_state_transport_security_plaintext(self):
        eml_explicit_pt = (
            "Received: from clear.mta (clear.mta [1.2.3.4]) by mx.dest.com with SMTP id 1; Wed, 15 Nov 2023 10:00:00 +0000\r\n"
            "From: sender@example.com\r\n"
            "Subject: Plaintext Transport\r\n\r\n"
            "Body\r\n"
        )
        report = EMLForensicAnalyzer.parse_eml_content(eml_explicit_pt)

        self.assertEqual(len(report.relay_chain), 1)
        hop = report.relay_chain[0]
        self.assertEqual(hop.transport_security_status, "PLAINTEXT_ASSERTED")
        self.assertEqual(hop.is_tls_encrypted, False)
        self.assertTrue(report.has_insecure_hop)

        # Explicit plaintext transport MUST trigger FINDING-EML-PLAINTEXT-RELAY-HOP
        pt_finding = next((f for f in report.findings if f["id"] == "FINDING-EML-PLAINTEXT-RELAY-HOP"), None)
        self.assertIsNotNone(pt_finding)

    # -----------------------------------------------------------------------
    # TEST 21: Header comparison wording uses "matches", not "aligns"
    # -----------------------------------------------------------------------
    def test_21_header_comparison_uses_matches_not_aligns(self):
        eml_matched = (
            "From: user@corp.com\r\n"
            "Sender: user@corp.com\r\n"
            "Reply-To: user@corp.com\r\n"
            "Return-Path: <user@corp.com>\r\n"
            "Message-ID: <123@corp.com>\r\n"
            "Subject: Match Wording\r\n\r\n"
            "Body\r\n"
        )
        report = EMLForensicAnalyzer.parse_eml_content(eml_matched)

        for rel in report.header_relationships:
            if rel.status == "MATCH":
                self.assertIn("matches", rel.description)
                self.assertNotIn("aligns", rel.description)


if __name__ == "__main__":
    unittest.main()
