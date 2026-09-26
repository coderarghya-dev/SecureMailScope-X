"""
SecureMailScope X - Cross-Case Correlation & Threat Intelligence Engine Tests (Phase 18)
Validates deterministic IOC extraction, canonical normalization, cross-analysis and
cross-case correlation discovery, graph topology construction, local search, STIX 2.1 export,
and REST API endpoints.
"""

import os
import sys
import json
import uuid
import tempfile
import unittest
from datetime import datetime, timezone
from typing import Optional
from fastapi.testclient import TestClient

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.main import app
from app.db.database import set_custom_db_path, init_db, get_db_connection
from app.db.repository import ForensicRepository
from app.services.case_service import CaseService
from app.services.correlation_service import (
    CorrelationService,
    normalize_ip,
    normalize_domain_or_hostname,
    normalize_email_address,
    normalize_cert_fingerprint,
    normalize_sha256_hash,
    normalize_mail_endpoint,
)
from app.schemas.correlation import (
    IOCType,
    CorrelationRelationshipType,
    GraphNodeType,
    GraphEdgeType,
)
from app.schemas.api import (
    AnalysisDetailResponse,
    SessionDetailDTO,
    STARTTLSStateDTO,
    TLSHandshakeDTO,
    CaptureHealthDTO,
    EvidenceConfidenceDTO,
    SecurityAssessmentDTO,
    SecurityFindingDTO,
    FindingsSummaryDTO,
    EvidenceFrameDTO,
    MultiSessionSummaryDTO,
)


def create_mock_analysis(
    analysis_id: str,
    client_ip: str = "192.168.1.50",
    server_ip: str = "198.51.100.25",
    server_port: int = 587,
    hostname: str = "mail.victim-corp.com",
    cert_fp: str = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
    from_addr: str = "attacker@evil-domain.org",
    finding_id: Optional[str] = None
) -> AnalysisDetailResponse:
    findings = []
    if finding_id:
        findings.append(SecurityFindingDTO(
            id=finding_id,
            title="Deprecated TLS Protocol",
            severity="HIGH",
            category="PROTOCOL_SECURITY",
            description="Use of TLS 1.0 observed",
            evidence_frames=[1, 2],
            recommendation="Upgrade to TLS 1.3"
        ))

    assessment = SecurityAssessmentDTO(
        grade="B" if not finding_id else "D",
        grade_rationale="Observation baseline",
        post_quantum_ready=False,
        post_quantum_summary="Classical KEX",
        findings_summary=FindingsSummaryDTO(critical=0, high=1 if finding_id else 0, medium=0, low=0, info=0),
        findings=findings
    )

    session = SessionDetailDTO(
        session_id=f"stream_0_{client_ip}_{server_ip}_{server_port}",
        stream_index=0,
        protocol="SMTP",
        security_mode="STARTTLS_ACCEPTED",
        client=f"{client_ip}:45678",
        server=f"{server_ip}:{server_port}",
        server_hostname=hostname,
        start_time_iso="2026-09-26T10:00:00Z",
        duration_seconds=1.5,
        packets_count=10,
        starttls=STARTTLSStateDTO(advertised=True, requested=True, accepted=True, upgrade_successful=True, state="UPGRADED"),
        tls=TLSHandshakeDTO(
            negotiated_version="TLSv1.2",
            cipher_name="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            forward_secrecy_pfs=True,
            pfs_status="ECDHE_PFS_ACTIVE",
            certificate_fingerprint_sha256=cert_fp,
            certificate_subject="CN=mail.victim-corp.com",
            certificate_issuer="CN=Global Forensic CA",
            certificate_visibility="FULL_CHAIN_OBSERVED"
        ),
        capture_health=CaptureHealthDTO(score=100, grade="EXCELLENT", syn_observed=True, fin_rst_observed=True, total_packets=10, retransmissions_count=0, retransmission_rate=0.0, deduction_reasons=[]),
        evidence_confidence=EvidenceConfidenceDTO(score=95, level="HIGH", handshake_observable=True, version_verifiable=True, cipher_identifiable=True, key_exchange_observable=True, confidence_factors=[]),
        security_assessment=assessment,
        evidence_frames=[EvidenceFrameDTO(frame=1, time_epoch=1727344800.0, protocol="SMTP", summary="STARTTLS upgrade")],
        eml_forensics={
            "from_address": from_addr,
            "to_address": "target@victim-corp.com",
            "return_path": from_addr,
            "message_id": f"<{analysis_id}.alert@evil-domain.org>",
        },
    )

    return AnalysisDetailResponse(
        analysis_id=analysis_id,
        file_name=f"{analysis_id}.pcap",
        file_size_bytes=4096,
        analysis_time_utc="2026-09-26T10:00:00Z",
        tshark_version="TShark 4.6.0",
        total_packets_extracted=10,
        raw_capture_packets_total=10,
        email_sessions_found=1,
        sessions=[session],
        evidence_confidence_score=95,
        evidence_confidence_level="HIGH",
        multi_session_summary=MultiSessionSummaryDTO(total_sessions=1, sessions_with_findings=len(findings), incident_count=0, critical_high_incident_count=0, repeated_pattern_count=0, uncorrelated_sessions_count=0),
        correlated_incidents=[],
    )


class TestCrossCaseCorrelation(unittest.TestCase):

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db", prefix="sms_corr_test_")
        os.close(self.temp_db_fd)
        set_custom_db_path(self.temp_db_path)
        init_db(self.temp_db_path)
        self.client = TestClient(app)

    def tearDown(self):
        set_custom_db_path(None)
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

    # 1. IP address normalization
    def test_01_ioc_ip_normalization(self):
        self.assertEqual(normalize_ip("192.168.1.1"), "192.168.1.1")
        self.assertEqual(normalize_ip("192.168.1.1:587"), "192.168.1.1")
        self.assertEqual(normalize_ip("[2001:db8::1]"), "2001:db8::1")
        self.assertEqual(normalize_ip("2001:db8::1"), "2001:db8::1")
        self.assertIsNone(normalize_ip("invalid-ip"))
        self.assertIsNone(normalize_ip("999.999.999.999"))

    # 2. Domain and Hostname normalization
    def test_02_ioc_domain_and_hostname_normalization(self):
        res1 = normalize_domain_or_hostname("MAIL.Victim-Corp.COM.")
        self.assertIsNotNone(res1)
        self.assertEqual(res1[0], "mail.victim-corp.com")
        self.assertEqual(res1[1], IOCType.HOSTNAME)

        res2 = normalize_domain_or_hostname("example.org")
        self.assertIsNotNone(res2)
        self.assertEqual(res2[0], "example.org")
        self.assertEqual(res2[1], IOCType.DOMAIN)

        self.assertIsNone(normalize_domain_or_hostname("invalid..domain"))
        self.assertIsNone(normalize_domain_or_hostname("192.168.1.1"))

    # 3. Email normalization
    def test_03_ioc_email_normalization(self):
        self.assertEqual(normalize_email_address("<Attacker@Evil-Domain.ORG>"), "attacker@evil-domain.org")
        self.assertEqual(normalize_email_address("user.name+tag@sub.example.com"), "user.name+tag@sub.example.com")
        self.assertIsNone(normalize_email_address("plainstring"))
        self.assertIsNone(normalize_email_address("no-domain@"))

    # 4. Certificate fingerprint normalization
    def test_04_ioc_cert_fingerprint_normalization(self):
        raw_fp = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"
        expected = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"
        self.assertEqual(normalize_cert_fingerprint(raw_fp), expected)
        self.assertIsNone(normalize_cert_fingerprint("short_hex"))

    # 5. Mail endpoint normalization
    def test_05_ioc_mail_endpoint_normalization(self):
        self.assertEqual(normalize_mail_endpoint("192.168.1.1", "587"), "192.168.1.1:587")
        self.assertEqual(normalize_mail_endpoint("192.168.1.1:587", "25"), "192.168.1.1:25")
        self.assertIsNone(normalize_mail_endpoint("invalid", "587"))
        self.assertIsNone(normalize_mail_endpoint("192.168.1.1", "999999"))

    # 6. Artifact SHA-256 normalization
    def test_06_ioc_artifact_sha256_normalization(self):
        valid_hash = "A" * 64
        self.assertEqual(normalize_sha256_hash(valid_hash), "a" * 64)
        self.assertIsNone(normalize_sha256_hash("tooshort"))

    # 7. IOC extraction provenance preservation
    def test_07_ioc_extraction_provenance_preservation(self):
        analysis = create_mock_analysis("analysis_prov_01", finding_id="FINDING-TLS-10")
        iocs = CorrelationService.extract_iocs_from_analysis(analysis, case_id="CASE-01")

        ip_iocs = [i for i in iocs if i.ioc_type == IOCType.IP_ADDRESS and i.normalized_value == "198.51.100.25"]
        self.assertTrue(len(ip_iocs) >= 1)
        prov = ip_iocs[0].provenance[0]
        self.assertEqual(prov.analysis_id, "analysis_prov_01")
        self.assertEqual(prov.case_id, "CASE-01")
        self.assertEqual(prov.protocol, "SMTP")
        self.assertEqual(prov.evidence_source, "PCAP_PACKET")
        self.assertIn("FINDING-TLS-10", ip_iocs[0].associated_findings)

    # 8. Deduplication within single analysis
    def test_08_ioc_deduplication_within_analysis(self):
        analysis = create_mock_analysis("analysis_dedup_01")
        analysis.sessions.append(analysis.sessions[0])
        iocs = CorrelationService.extract_iocs_from_analysis(analysis)

        ip_iocs = [i for i in iocs if i.ioc_type == IOCType.IP_ADDRESS and i.normalized_value == "198.51.100.25"]
        self.assertEqual(len(ip_iocs), 1)
        self.assertEqual(ip_iocs[0].observation_count, 2)
        self.assertEqual(len(ip_iocs[0].provenance), 2)

    # 9. Cross-analysis shared IP correlation
    def test_09_cross_analysis_shared_ip_correlation(self):
        shared_ip = "198.51.100.99"
        a1 = create_mock_analysis("analysis_shared_ip_1", server_ip=shared_ip, hostname="srv1.domain1.org")
        a2 = create_mock_analysis("analysis_shared_ip_2", server_ip=shared_ip, hostname="srv2.domain2.org")

        ForensicRepository.save_analysis(a1, db_path=self.temp_db_path)
        ForensicRepository.save_analysis(a2, db_path=self.temp_db_path)

        correlations = CorrelationService.compute_correlations(db_path=self.temp_db_path)
        ip_corrs = [c for c in correlations if c.ioc_type == IOCType.IP_ADDRESS and c.ioc_value == shared_ip]

        self.assertEqual(len(ip_corrs), 1)
        self.assertEqual(ip_corrs[0].relationship_type, CorrelationRelationshipType.SHARED_IP)
        self.assertIn("analysis_shared_ip_1", ip_corrs[0].matched_analyses)
        self.assertIn("analysis_shared_ip_2", ip_corrs[0].matched_analyses)
        self.assertTrue("Observed IP_ADDRESS" in ip_corrs[0].evidence_summary)

    # 10. Cross-analysis shared certificate correlation
    def test_10_cross_analysis_shared_cert_correlation(self):
        cert_raw = "11:22:33:44:55:66:77:88:99:00:11:22:33:44:55:66:77:88:99:00:11:22:33:44:55:66:77:88:99:00:11:22"
        expected_norm = normalize_cert_fingerprint(cert_raw)

        a1 = create_mock_analysis("analysis_cert_1", cert_fp=cert_raw, server_ip="192.0.2.1")
        a2 = create_mock_analysis("analysis_cert_2", cert_fp=cert_raw, server_ip="192.0.2.2")

        ForensicRepository.save_analysis(a1, db_path=self.temp_db_path)
        ForensicRepository.save_analysis(a2, db_path=self.temp_db_path)

        correlations = CorrelationService.compute_correlations(db_path=self.temp_db_path)
        cert_corrs = [c for c in correlations if c.ioc_type == IOCType.CERTIFICATE_FINGERPRINT and c.ioc_value == expected_norm]

        self.assertEqual(len(cert_corrs), 1)
        self.assertEqual(cert_corrs[0].relationship_type, CorrelationRelationshipType.SHARED_CERTIFICATE)
        self.assertEqual(len(cert_corrs[0].matched_analyses), 2)

    # 11. Cross-analysis shared domain correlation
    def test_11_cross_analysis_shared_domain_correlation(self):
        a1 = create_mock_analysis("analysis_dom_1", hostname="mx1.shared-threat.com")
        a2 = create_mock_analysis("analysis_dom_2", hostname="mx2.shared-threat.com")

        ForensicRepository.save_analysis(a1, db_path=self.temp_db_path)
        ForensicRepository.save_analysis(a2, db_path=self.temp_db_path)

        correlations = CorrelationService.compute_correlations(db_path=self.temp_db_path)
        dom_corrs = [c for c in correlations if c.ioc_type == IOCType.DOMAIN and c.ioc_value == "shared-threat.com"]

        self.assertEqual(len(dom_corrs), 1)
        self.assertEqual(dom_corrs[0].relationship_type, CorrelationRelationshipType.SHARED_DOMAIN)

    # 12. Cross-case correlation linkage
    def test_12_cross_case_correlation_linkage(self):
        shared_ip = "203.0.113.88"
        a1 = create_mock_analysis("analysis_case_link_1", server_ip=shared_ip)
        a2 = create_mock_analysis("analysis_case_link_2", server_ip=shared_ip)

        ForensicRepository.save_analysis(a1, db_path=self.temp_db_path)
        ForensicRepository.save_analysis(a2, db_path=self.temp_db_path)

        c1 = CaseService.create_case(title="Case Alpha", db_path=self.temp_db_path)
        c2 = CaseService.create_case(title="Case Beta", db_path=self.temp_db_path)

        CaseService.attach_analysis_to_case(c1.id, "analysis_case_link_1", db_path=self.temp_db_path)
        CaseService.attach_analysis_to_case(c2.id, "analysis_case_link_2", db_path=self.temp_db_path)

        correlations = CorrelationService.compute_correlations(db_path=self.temp_db_path)
        ip_corrs = [c for c in correlations if c.ioc_type == IOCType.IP_ADDRESS and c.ioc_value == shared_ip]

        self.assertEqual(len(ip_corrs), 1)
        self.assertIn(c1.id, ip_corrs[0].matched_cases)
        self.assertIn(c2.id, ip_corrs[0].matched_cases)

    # 13. Uncorrelated indicators below threshold
    def test_13_uncorrelated_indicators_below_threshold(self):
        unique_ip = "198.51.100.77"
        a1 = create_mock_analysis("analysis_isolated_1", server_ip=unique_ip)
        ForensicRepository.save_analysis(a1, db_path=self.temp_db_path)

        correlations = CorrelationService.compute_correlations(db_path=self.temp_db_path)
        unique_matches = [c for c in correlations if c.ioc_value == unique_ip]
        self.assertEqual(len(unique_matches), 0)

    # 14. Correlation risk context attached
    def test_14_correlation_risk_context_attached(self):
        shared_ip = "198.51.100.66"
        a1 = create_mock_analysis("analysis_risk_1", server_ip=shared_ip, finding_id="FINDING-STATIC-RSA")
        a2 = create_mock_analysis("analysis_risk_2", server_ip=shared_ip)

        ForensicRepository.save_analysis(a1, db_path=self.temp_db_path)
        ForensicRepository.save_analysis(a2, db_path=self.temp_db_path)

        correlations = CorrelationService.compute_correlations(db_path=self.temp_db_path)
        ip_corrs = [c for c in correlations if c.ioc_value == shared_ip]

        self.assertEqual(len(ip_corrs), 1)
        self.assertIsNotNone(ip_corrs[0].risk_context)
        self.assertIn("FINDING-STATIC-RSA", ip_corrs[0].risk_context)

    # 15. Correlation graph generation
    def test_15_correlation_graph_generation(self):
        shared_ip = "198.51.100.55"
        a1 = create_mock_analysis("analysis_graph_1", server_ip=shared_ip)
        a2 = create_mock_analysis("analysis_graph_2", server_ip=shared_ip)

        ForensicRepository.save_analysis(a1, db_path=self.temp_db_path)
        ForensicRepository.save_analysis(a2, db_path=self.temp_db_path)

        c1 = CaseService.create_case(title="Graph Test Case", db_path=self.temp_db_path)
        CaseService.attach_analysis_to_case(c1.id, "analysis_graph_1", db_path=self.temp_db_path)

        graph = CorrelationService.build_correlation_graph(db_path=self.temp_db_path)

        self.assertTrue(graph.total_nodes >= 3)
        self.assertTrue(graph.total_edges >= 2)

        node_types = set(n.node_type for n in graph.nodes)
        self.assertIn(GraphNodeType.CASE, node_types)
        self.assertIn(GraphNodeType.ANALYSIS, node_types)
        self.assertIn(GraphNodeType.IP, node_types)

        edge_types = set(e.edge_type for e in graph.edges)
        self.assertIn(GraphEdgeType.CASE_CONTAINS_ANALYSIS, edge_types)
        self.assertIn(GraphEdgeType.ANALYSIS_OBSERVED_IP, edge_types)

    # 16. Correlation graph filtering
    def test_16_correlation_graph_filtering(self):
        a1 = create_mock_analysis("analysis_filter_1", server_ip="198.51.100.11")
        a2 = create_mock_analysis("analysis_filter_2", server_ip="198.51.100.22")

        ForensicRepository.save_analysis(a1, db_path=self.temp_db_path)
        ForensicRepository.save_analysis(a2, db_path=self.temp_db_path)

        filtered_graph = CorrelationService.build_correlation_graph(analysis_id="analysis_filter_1", db_path=self.temp_db_path)
        analysis_nodes = [n for n in filtered_graph.nodes if n.node_type == GraphNodeType.ANALYSIS]
        self.assertEqual(len(analysis_nodes), 1)
        self.assertEqual(analysis_nodes[0].node_id, "analysis:analysis_filter_1")

    # 17. Local IOC search exact and substring
    def test_17_local_ioc_search_exact_and_substring(self):
        target_email = "target.victim@corpHQ.com"
        a1 = create_mock_analysis("analysis_search_1", from_addr=target_email)
        ForensicRepository.save_analysis(a1, db_path=self.temp_db_path)

        res = CorrelationService.search_iocs(query="victim", db_path=self.temp_db_path)
        self.assertTrue(len(res.matched_iocs) >= 1)
        self.assertIn("analysis_search_1", res.linked_analyses)

        res_exact = CorrelationService.search_iocs(query="target.victim@corphq.com", db_path=self.temp_db_path)
        self.assertEqual(len(res_exact.matched_iocs), 1)
        self.assertEqual(res_exact.matched_iocs[0].normalized_value, "target.victim@corphq.com")

    # 18. STIX 2.1 bundle export format
    def test_18_stix21_bundle_export_format(self):
        shared_ip = "198.51.100.44"
        a1 = create_mock_analysis("analysis_stix_1", server_ip=shared_ip)
        a2 = create_mock_analysis("analysis_stix_2", server_ip=shared_ip)

        ForensicRepository.save_analysis(a1, db_path=self.temp_db_path)
        ForensicRepository.save_analysis(a2, db_path=self.temp_db_path)

        bundle = CorrelationService.export_stix21_bundle(db_path=self.temp_db_path)

        self.assertEqual(bundle["type"], "bundle")
        self.assertEqual(bundle["spec_version"], "2.1")
        self.assertTrue(bundle["id"].startswith("bundle--"))

        obj_types = [o["type"] for o in bundle["objects"]]
        self.assertIn("identity", obj_types)
        self.assertIn("ipv4-addr", obj_types)
        self.assertIn("relationship", obj_types)

    # 19. API endpoints correlation summary, search, and graph
    def test_19_api_endpoints_correlation_summary_and_search(self):
        shared_ip = "198.51.100.33"
        a1 = create_mock_analysis("analysis_api_1", server_ip=shared_ip)
        a2 = create_mock_analysis("analysis_api_2", server_ip=shared_ip)

        ForensicRepository.save_analysis(a1, db_path=self.temp_db_path)
        ForensicRepository.save_analysis(a2, db_path=self.temp_db_path)

        # Summary Endpoint
        resp_sum = self.client.get("/api/v1/correlation/summary")
        self.assertEqual(resp_sum.status_code, 200)
        sum_data = resp_sum.json()
        self.assertTrue(sum_data["total_analyses_evaluated"] >= 2)
        self.assertTrue(sum_data["total_relationships"] >= 1)

        # Search Endpoint
        resp_search = self.client.get(f"/api/v1/correlation/search?value={shared_ip}&ioc_type=IP_ADDRESS")
        self.assertEqual(resp_search.status_code, 200)
        search_data = resp_search.json()
        self.assertEqual(len(search_data["matched_iocs"]), 1)
        self.assertEqual(search_data["matched_iocs"][0]["normalized_value"], shared_ip)

        # Graph Endpoint
        resp_graph = self.client.get("/api/v1/correlation/graph")
        self.assertEqual(resp_graph.status_code, 200)
        graph_data = resp_graph.json()
        self.assertTrue(graph_data["total_nodes"] >= 2)

    # 20. API endpoints case and analysis drilldown and STIX download
    def test_20_api_endpoints_case_and_analysis_drilldown(self):
        shared_ip = "198.51.100.12"
        a1 = create_mock_analysis("analysis_drill_1", server_ip=shared_ip)
        a2 = create_mock_analysis("analysis_drill_2", server_ip=shared_ip)

        ForensicRepository.save_analysis(a1, db_path=self.temp_db_path)
        ForensicRepository.save_analysis(a2, db_path=self.temp_db_path)

        c1 = CaseService.create_case(title="Drilldown Case", db_path=self.temp_db_path)
        CaseService.attach_analysis_to_case(c1.id, "analysis_drill_1", db_path=self.temp_db_path)

        # Analysis correlation drilldown
        resp_a = self.client.get("/api/v1/analyses/analysis_drill_1/correlations")
        self.assertEqual(resp_a.status_code, 200)
        a_corrs = resp_a.json()
        self.assertTrue(len(a_corrs) >= 1)

        # Case correlation drilldown
        resp_c = self.client.get(f"/api/v1/cases/{c1.id}/correlations")
        self.assertEqual(resp_c.status_code, 200)
        c_corrs = resp_c.json()
        self.assertTrue(len(c_corrs) >= 1)

        # STIX Export Download Endpoint
        resp_stix = self.client.get("/api/v1/correlation/export/stix")
        self.assertEqual(resp_stix.status_code, 200)
        stix_bundle = resp_stix.json()
        self.assertEqual(stix_bundle["type"], "bundle")
        self.assertIn("sms_stix21_correlation_bundle.json", resp_stix.headers.get("content-disposition", ""))


if __name__ == "__main__":
    unittest.main()
