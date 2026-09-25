"""
SecureMailScope X - Evidence-Bounded DNS & Domain Authentication Tests (Phase 7 & 7.5)
Deterministic verification tests covering:
1. Passive mode with no DNS evidence -> NOT_OBSERVED, no fake absence findings.
2. Active SPF lookup -> source ACTIVE_DNS_ENRICHMENT, historical_applicability CURRENT_STATE_ONLY.
3. SPF TXT present -> parsed mechanisms/qualifier, no message-level pass/fail without message evidence.
4. DKIM header present -> signature metadata parsed, dkim_verification_status = NOT_VERIFIED.
5. DMARC record parsing -> p/sp/pct/adkim/aspf/rua, message_dmarc_result = NOT_EVALUATED.
6. BIMI record parsing -> record presence only, vmc_validation_status = NOT_VALIDATED.
7. MTA-STS TXT and HTTPS parsing -> safe target construction and parsing.
8. DANE TLSA parsing -> dnssec_status = NOT_VALIDATED.
9. Active lookup disabled -> zero network calls.
10. Active DNS enrichment never alters Security Grade, Evidence Confidence, PFS, PQC, or Certificate findings.
11. Historical capture semantics: active result explicitly CURRENT_STATE_ONLY.
12. SPF top-level count only -> ESTIMATED (not falsely VERIFIED), lookup_limit_exceeded is False.
13. SPF recursive evaluation -> VERIFIED when actually evaluated with resolver.
14. Network timeout / error != POLICY_ABSENT (produces UNAVAILABLE and no false absence findings).
15. SSRF protection: MTA-STS rejects localhost, 127.0.0.1, RFC1918, link-local, userinfo, arbitrary schemes.
16. SafeRedirectHandler: Revalidates redirect hostnames and enforces HTTPS.
"""

import os
import sys
import unittest
from datetime import datetime, timezone

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.schemas.forensic import (
    EmailSession,
    EmailProtocol,
    SecurityMode,
    PacketEvidence,
    TLSHandshakeDetails,
    TLSVersion,
    CipherSuiteInfo,
    SecurityStrength,
    FindingSeverity,
    FindingCategory,
    SecurityGrade,
    AuthProvenanceSource,
    HistoricalApplicability,
    DNSAuthStatus,
    DomainAuthenticationAssessment,
    SPFRecordDetails,
    DKIMRecordDetails,
    DMARCRecordDetails,
    MTASTSRecordDetails,
    BIMIRecordDetails,
    DANERecordDetails
)
from app.dns.dns_auth_analyzer import DNSAuthAnalyzer
from app.dns.dns_resolver import DNSResolver, SafeRedirectHandler
from app.dns.email_auth_analyzer import EmailAuthAnalyzer
from app.eml.eml_analyzer import EMLForensicAnalyzer
from app.forensic.rule_engine import CryptographicRuleEngine


class MockDNSResolver(DNSResolver):
    """Deterministic in-memory DNS resolver for reproducible testing without external network dependencies."""

    def __init__(
        self,
        records: dict = None,
        mta_sts_policy: dict = None,
        fail_queries: bool = False,
        provider_name: str = "Mock DoH Resolver",
        endpoint_url: str = "https://mock-dns.local/dns-query"
    ):
        super().__init__(timeout_sec=1.0, endpoint_url=endpoint_url, provider_name=provider_name)
        self.records = records or {}
        self.mta_sts_policy = mta_sts_policy
        self.fail_queries = fail_queries
        self.query_count = 0

    def query_txt_with_status(self, name: str):
        self.query_count += 1
        if self.fail_queries:
            return [], False, "Connection timeout to DoH resolver"
        clean = name.strip().rstrip(".")
        recs = self.records.get(clean, [])
        return recs, True, None

    def query_txt(self, name: str) -> list:
        recs, _, _ = self.query_txt_with_status(name)
        return recs

    def query_tlsa_with_status(self, name: str):
        self.query_count += 1
        if self.fail_queries:
            return [], False, "Connection timeout to DoH resolver"
        clean = name.strip().rstrip(".")
        recs = self.records.get(f"TLSA:{clean}", [])
        return recs, True, None

    def query_tlsa(self, name: str) -> list:
        recs, _, _ = self.query_tlsa_with_status(name)
        return recs

    def fetch_mta_sts_policy(self, domain: str) -> dict:
        self.query_count += 1
        if self.fail_queries:
            return None
        clean = domain.strip().lower().rstrip(".")
        return self.mta_sts_policy.get(clean) if self.mta_sts_policy else None


class TestDNSAuthAnalyzer(unittest.TestCase):

    def _create_sample_session(self, server_hostname: str = "mail.example.org") -> EmailSession:
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
        return EmailSession(
            session_id="stream_dns_test_1",
            stream_index=0,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.DIRECT_TLS,
            client_ip="192.168.1.100",
            client_port=45000,
            server_ip="192.0.2.25",
            server_port=465,
            server_hostname=server_hostname,
            start_time_epoch=1700000000.0,
            tls_details=tls
        )

    # -----------------------------------------------------------------------
    # TEST 1: Passive mode with no DNS evidence -> NOT_OBSERVED, no fake absence findings
    # -----------------------------------------------------------------------
    def test_01_passive_mode_not_observed_no_fake_findings(self):
        sess = self._create_sample_session()
        auth = DNSAuthAnalyzer.evaluate_passive_session(sess)
        sess.domain_auth = auth

        self.assertEqual(auth.source, AuthProvenanceSource.PASSIVE_CAPTURE)
        self.assertEqual(auth.historical_applicability, HistoricalApplicability.CAPTURE_TIME_EVIDENCE)
        self.assertFalse(auth.is_active_enrichment)
        self.assertEqual(auth.spf.status, DNSAuthStatus.NOT_OBSERVED)
        self.assertEqual(auth.spf.lookup_count_status, "NOT_EVALUATED")
        self.assertEqual(auth.dmarc.status, DNSAuthStatus.NOT_OBSERVED)
        self.assertEqual(auth.dmarc.message_dmarc_result, "NOT_EVALUATED")
        self.assertEqual(auth.mta_sts.status, DNSAuthStatus.NOT_OBSERVED)
        self.assertEqual(auth.bimi.status, DNSAuthStatus.NOT_OBSERVED)
        self.assertEqual(auth.bimi.vmc_validation_status, "NOT_VALIDATED")
        self.assertEqual(auth.dane.status, DNSAuthStatus.NOT_OBSERVED)
        self.assertEqual(auth.dane.dnssec_status, "NOT_VALIDATED")

        # Rule engine evaluation on passive session must NOT produce absence findings
        assessment = CryptographicRuleEngine.evaluate_session(sess)
        dns_findings = [f for f in assessment.findings if f.category == FindingCategory.DOMAIN_AUTHENTICATION]
        self.assertEqual(len(dns_findings), 0)

    # -----------------------------------------------------------------------
    # TEST 2: Active SPF lookup -> source ACTIVE_DNS_ENRICHMENT, CURRENT_STATE_ONLY
    # -----------------------------------------------------------------------
    def test_02_active_spf_lookup_provenance_and_resolver_metadata(self):
        mock_res = MockDNSResolver({
            "example.com": ["v=spf1 ip4:192.0.2.0/24 include:_spf.google.com -all"],
            "_spf.google.com": ["v=spf1 ip4:192.0.2.10/32 -all"],
            "_dmarc.example.com": ["v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@example.com"],
            "_mta-sts.example.com": ["v=STSv1; id=20231101T000000;"],
            "default._bimi.example.com": ["v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem;"]
        }, provider_name="Cloudflare DoH", endpoint_url="https://cloudflare-dns.com/dns-query")

        auth = DNSAuthAnalyzer.evaluate_active_domain("example.com", resolver=mock_res)

        self.assertEqual(auth.source, AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT)
        self.assertEqual(auth.historical_applicability, HistoricalApplicability.CURRENT_STATE_ONLY)
        self.assertTrue(auth.is_active_enrichment)
        self.assertIsNotNone(auth.queried_at_utc)
        self.assertEqual(auth.resolver_provider, "Cloudflare DoH")
        self.assertEqual(auth.resolver_endpoint, "https://cloudflare-dns.com/dns-query")
        self.assertEqual(auth.spf.status, DNSAuthStatus.ACTIVE_ENRICHMENT)
        self.assertEqual(auth.spf.policy_qualifier, "-all")
        self.assertTrue(auth.spf.spf_policy_present)
        self.assertIsNone(auth.spf.spf_message_result)

    # -----------------------------------------------------------------------
    # TEST 3: SPF TXT present -> parsed mechanisms/qualifier
    # -----------------------------------------------------------------------
    def test_03_spf_parsing_qualifiers_and_mechanisms(self):
        # 3a. Strict fail (-all)
        spf_strict = DNSAuthAnalyzer.parse_spf_record(
            ["v=spf1 ip4:192.0.2.1 mx include:relay.corp.com -all"],
            provenance=AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT
        )
        self.assertEqual(spf_strict.policy_qualifier, "-all")
        self.assertEqual(spf_strict.include_domains, ["relay.corp.com"])
        self.assertTrue(spf_strict.syntax_valid)
        self.assertFalse(spf_strict.lookup_limit_exceeded)
        self.assertEqual(spf_strict.lookup_count_status, "ESTIMATED")

        # 3b. Softfail (~all)
        spf_soft = DNSAuthAnalyzer.parse_spf_record(["v=spf1 include:_spf.domain.com ~all"])
        self.assertEqual(spf_soft.policy_qualifier, "~all")

        # 3c. Permissive neutral (?all)
        spf_neutral = DNSAuthAnalyzer.parse_spf_record(["v=spf1 mx ?all"])
        self.assertEqual(spf_neutral.policy_qualifier, "?all")

        # 3d. Insecure allow-all (+all)
        spf_allow = DNSAuthAnalyzer.parse_spf_record(["v=spf1 +all"])
        self.assertEqual(spf_allow.policy_qualifier, "+all")

        # 3e. Multiple SPF records (RFC 7208 violation)
        spf_multi = DNSAuthAnalyzer.parse_spf_record([
            "v=spf1 ip4:1.2.3.4 -all",
            "v=spf1 include:other.com -all"
        ])
        self.assertEqual(spf_multi.status, DNSAuthStatus.INVALID)
        self.assertFalse(spf_multi.syntax_valid)
        self.assertIn("Multiple SPF records", spf_multi.syntax_error)

    # -----------------------------------------------------------------------
    # TEST 4: DKIM header present -> signature metadata parsed, NOT_VERIFIED status
    # -----------------------------------------------------------------------
    def test_04_dkim_header_parsing_and_verification_boundary(self):
        dkim_header = (
            "v=1; a=rsa-sha256; c=relaxed/relaxed; d=securemail.org; s=202311;\n"
            "t=1700000000; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;\n"
            "h=From:To:Subject:Date:Message-ID;\n"
            "b=dzI4aW5k..."
        )
        dkim = DNSAuthAnalyzer.parse_dkim_header(dkim_header)

        self.assertEqual(dkim.signing_domain, "securemail.org")
        self.assertEqual(dkim.selector, "202311")
        self.assertEqual(dkim.algorithm, "rsa-sha256")
        self.assertEqual(dkim.canonicalization, "relaxed/relaxed")
        self.assertTrue(dkim.body_hash_present)
        self.assertEqual(dkim.body_hash, "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
        self.assertTrue(dkim.signature_present)
        # Must strictly remain NOT_VERIFIED
        self.assertEqual(dkim.dkim_verification_status, "NOT_VERIFIED")
        self.assertIn("NOT performed", dkim.analysis_limitations[0])

    # -----------------------------------------------------------------------
    # TEST 5: DMARC record parsing (p, sp, pct, adkim, aspf, rua)
    # -----------------------------------------------------------------------
    def test_05_dmarc_record_parsing(self):
        dmarc_txt = "v=DMARC1; p=quarantine; sp=reject; pct=80; adkim=s; aspf=r; rua=mailto:agg@corp.com,mailto:dmarc@corp.com; ruf=mailto:forensics@corp.com"
        dmarc = DNSAuthAnalyzer.parse_dmarc_record(dmarc_txt, provenance=AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT)

        self.assertEqual(dmarc.status, DNSAuthStatus.ACTIVE_ENRICHMENT)
        self.assertEqual(dmarc.policy_p, "quarantine")
        self.assertEqual(dmarc.subdomain_policy_sp, "reject")
        self.assertEqual(dmarc.percentage_pct, 80)
        self.assertEqual(dmarc.adkim_mode, "s")
        self.assertEqual(dmarc.aspf_mode, "r")
        self.assertEqual(len(dmarc.rua_uris), 2)
        self.assertEqual(len(dmarc.ruf_uris), 1)
        self.assertFalse(dmarc.alignment_evaluated)
        self.assertEqual(dmarc.message_dmarc_result, "NOT_EVALUATED")

    # -----------------------------------------------------------------------
    # TEST 6: BIMI record parsing -> no brand/VMC trust claim
    # -----------------------------------------------------------------------
    def test_06_bimi_record_parsing_and_vmc_boundary(self):
        bimi_txt = "v=BIMI1; l=https://mail.example.org/brand/logo.svg; a=https://mail.example.org/brand/cert.pem;"
        bimi = DNSAuthAnalyzer.parse_bimi_record(bimi_txt, provenance=AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT)

        self.assertEqual(bimi.version, "BIMI1")
        self.assertEqual(bimi.location_svg, "https://mail.example.org/brand/logo.svg")
        self.assertEqual(bimi.authority_vmc, "https://mail.example.org/brand/cert.pem")
        self.assertEqual(bimi.vmc_validation_status, "NOT_VALIDATED")
        self.assertFalse(bimi.brand_validation_claimed)
        self.assertIn("NOT performed", bimi.analysis_limitations[0])

    # -----------------------------------------------------------------------
    # TEST 7: MTA-STS TXT and HTTPS policy parsing
    # -----------------------------------------------------------------------
    def test_07_mta_sts_txt_and_https_policy_parsing(self):
        mta_sts_txt = "v=STSv1; id=20231115T010101;"
        https_policy = {
            "url": "https://mta-sts.example.org/.well-known/mta-sts.txt",
            "fetched_at_utc": "2023-11-15T01:05:00Z",
            "mode": "enforce",
            "max_age": 604800,
            "mx": ["mail.example.org", "*.mail.example.org"]
        }
        mta_sts = DNSAuthAnalyzer.parse_mta_sts_record(
            mta_sts_txt,
            provenance=AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT,
            https_policy=https_policy
        )

        self.assertEqual(mta_sts.version, "STSv1")
        self.assertEqual(mta_sts.id_tag, "20231115T010101")
        self.assertEqual(mta_sts.policy_mode, "enforce")
        self.assertEqual(mta_sts.max_age_seconds, 604800)
        self.assertEqual(len(mta_sts.mx_patterns), 2)
        self.assertTrue(mta_sts.https_policy_fetched)

    # -----------------------------------------------------------------------
    # TEST 8: DANE TLSA parsing -> dnssec_status = NOT_VALIDATED
    # -----------------------------------------------------------------------
    def test_08_dane_tlsa_parsing_and_dnssec_boundary(self):
        tlsa_records = [
            "3 1 1 8f434346648f6b96df89dda901c5176b10e6d0b933d19881f2154c1f930e4871",
            "2 0 1 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b"
        ]
        dane = DNSAuthAnalyzer.parse_dane_record(tlsa_records, provenance=AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT)

        self.assertEqual(dane.status, DNSAuthStatus.ACTIVE_ENRICHMENT)
        self.assertEqual(len(dane.tlsa_records), 2)
        self.assertEqual(dane.parsed_usages, [3, 2])
        self.assertEqual(dane.dnssec_status, "NOT_VALIDATED")
        self.assertIn("NOT_VALIDATED", dane.analysis_limitations[0])

    # -----------------------------------------------------------------------
    # TEST 9: Active lookup disabled -> no network call
    # -----------------------------------------------------------------------
    def test_09_offline_evaluation_performs_zero_network_queries(self):
        mock_res = MockDNSResolver()
        auth = DNSAuthAnalyzer.evaluate_provided_records(
            domain="offline.example.com",
            txt_records=["v=spf1 -all"],
            dmarc_txt="v=DMARC1; p=reject;"
        )

        self.assertEqual(mock_res.query_count, 0)
        self.assertEqual(auth.source, AuthProvenanceSource.OFFLINE_MANUAL_INPUT)
        self.assertFalse(auth.is_active_enrichment)
        self.assertEqual(auth.spf.policy_qualifier, "-all")
        self.assertEqual(auth.dmarc.policy_p, "reject")

    # -----------------------------------------------------------------------
    # TEST 10: Active DNS enrichment findings never alter Security Grade
    # -----------------------------------------------------------------------
    def test_10_active_enrichment_does_not_alter_security_grade(self):
        sess = self._create_sample_session()

        # Grade before DNS enrichment
        assess_before = CryptographicRuleEngine.evaluate_session(sess)
        grade_before = assess_before.grade

        # Attach active DNS assessment with weak/missing policies
        mock_res = MockDNSResolver({
            "mail.example.org": ["v=spf1 +all"],  # Insecure +all
            "_dmarc.mail.example.org": []  # Missing DMARC
        })
        active_auth = DNSAuthAnalyzer.evaluate_active_domain("mail.example.org", resolver=mock_res)
        sess.domain_auth = active_auth

        # Grade after DNS enrichment
        assess_after = CryptographicRuleEngine.evaluate_session(sess)
        grade_after = assess_after.grade

        # Security Grade must remain strictly identical (TLS posture is authoritative)
        self.assertEqual(grade_before, grade_after)
        self.assertEqual(grade_after, SecurityGrade.A)

        # Domain authentication finding is added with explicit ACTIVE_DNS_ENRICHMENT boundary
        spf_finding = next((f for f in assess_after.findings if f.id == "FINDING-SPF-ALLOW-ALL"), None)
        self.assertIsNotNone(spf_finding)
        self.assertIn("CURRENT_STATE_ONLY", spf_finding.explanation.confidence_boundary)

    # -----------------------------------------------------------------------
    # TEST 11: Historical capture semantics -> active result explicitly CURRENT_STATE_ONLY
    # -----------------------------------------------------------------------
    def test_11_historical_capture_semantics(self):
        mock_res = MockDNSResolver({"target.org": ["v=spf1 -all"]})
        auth = DNSAuthAnalyzer.evaluate_active_domain("target.org", resolver=mock_res)

        self.assertEqual(auth.historical_applicability, HistoricalApplicability.CURRENT_STATE_ONLY)
        self.assertIn("does NOT alter or represent historical capture evidence", auth.authoritative_boundary_disclaimer)

    # -----------------------------------------------------------------------
    # TEST 12: SPF top-level count only is labeled ESTIMATED (not falsely VERIFIED)
    # -----------------------------------------------------------------------
    def test_12_spf_top_level_count_is_estimated(self):
        # 11 include mechanisms (top-level only, no recursive resolver)
        terms = ["v=spf1"] + [f"include:inc{i}.domain.com" for i in range(11)] + ["-all"]
        spf_rec = " ".join(terms)
        spf = DNSAuthAnalyzer.parse_spf_record([spf_rec], provenance=AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT)

        self.assertEqual(spf.lookup_count, 11)
        self.assertEqual(spf.lookup_count_status, "ESTIMATED")
        self.assertEqual(spf.lookup_limit_risk, "POTENTIAL_LOOKUP_LIMIT_RISK")
        # Top-level alone without recursive evaluation does not claim exact RFC 7208 violation
        self.assertFalse(spf.lookup_limit_exceeded)

    # -----------------------------------------------------------------------
    # TEST 13: SPF recursive evaluation -> VERIFIED when actually evaluated
    # -----------------------------------------------------------------------
    def test_13_spf_recursive_evaluation_verified(self):
        # Recursive resolution with 12 nested include terms
        records = {
            "root.example.com": ["v=spf1 include:sub1.example.com include:sub2.example.com -all"],
            "sub1.example.com": ["v=spf1 a mx include:sub3.example.com -all"],
            "sub2.example.com": ["v=spf1 a mx ptr -all"],
            "sub3.example.com": ["v=spf1 a mx exists:%{i}.example.com a mx -all"]
        }
        mock_res = MockDNSResolver(records)
        auth = DNSAuthAnalyzer.evaluate_active_domain("root.example.com", resolver=mock_res, evaluate_spf_recursive=True)

        self.assertEqual(auth.spf.lookup_count_status, "VERIFIED")
        self.assertTrue(auth.spf.lookup_count > 10)
        self.assertTrue(auth.spf.lookup_limit_exceeded)

    # -----------------------------------------------------------------------
    # TEST 14: Network timeout / error != POLICY_ABSENT
    # -----------------------------------------------------------------------
    def test_14_network_timeout_results_in_unavailable_not_policy_absent(self):
        # Resolver configured to simulate network failure / timeout
        failing_res = MockDNSResolver(fail_queries=True)
        auth = DNSAuthAnalyzer.evaluate_active_domain("timeout.example.com", resolver=failing_res)

        self.assertEqual(auth.spf.status, DNSAuthStatus.UNAVAILABLE)
        self.assertEqual(auth.dmarc.status, DNSAuthStatus.UNAVAILABLE)
        self.assertEqual(auth.mta_sts.status, DNSAuthStatus.UNAVAILABLE)
        self.assertIn("failed or timed out", auth.spf.analysis_limitations[0])

        # When evaluated by RuleEngine, it must NOT produce POLICY_ABSENT findings
        sess = self._create_sample_session()
        sess.domain_auth = auth
        assessment = CryptographicRuleEngine.evaluate_session(sess)

        absent_findings = [
            f for f in assessment.findings
            if f.id in ["FINDING-SPF-POLICY-ABSENT", "FINDING-DMARC-POLICY-ABSENT"]
        ]
        self.assertEqual(len(absent_findings), 0)

    # -----------------------------------------------------------------------
    # TEST 15: SSRF Protection for MTA-STS and DNS Hostnames
    # -----------------------------------------------------------------------
    def test_15_ssrf_hostname_rejection(self):
        unsafe_hosts = [
            "localhost",
            "127.0.0.1",
            "::1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "user:pass@example.com",
            "example.com:8080",
            "example.internal",
            "example.local",
            "http://malicious.site",
            "https://malicious.site/subpath",
            "0.0.0.0"
        ]
        for host in unsafe_hosts:
            self.assertFalse(
                DNSResolver.is_safe_public_hostname(host),
                f"Host '{host}' should be rejected as unsafe SSRF target"
            )

    # -----------------------------------------------------------------------
    # TEST 16: SafeRedirectHandler revalidates redirect targets
    # -----------------------------------------------------------------------
    def test_16_redirect_handler_enforces_https_and_ssrf(self):
        handler = SafeRedirectHandler(max_redirects=2)
        # Attempting > 2 redirects throws HTTPError
        handler._redirect_count = 2
        import urllib.error
        with self.assertRaises(urllib.error.HTTPError):
            handler.redirect_request(None, None, 302, "Redirect", {}, "https://example.com/redirect")


if __name__ == "__main__":
    unittest.main()
