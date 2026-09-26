"""
SecureMailScope X - Cross-Case Correlation & IOC Intelligence Engine Service (Phase 18)
Provides deterministic IOC extraction, cross-case/cross-analysis correlation analysis,
graph topology generation, local offline search, and STIX 2.1 JSON bundle export.
"""

import re
import ipaddress
import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict

from app.db.database import get_db_connection
from app.db.repository import ForensicRepository
from app.schemas.api import AnalysisDetailResponse
from app.schemas.correlation import (
    IOCType,
    CorrelationRelationshipType,
    IOCProvenance,
    NormalizedIOC,
    CorrelationRelationship,
    GraphNodeType,
    GraphEdgeType,
    CorrelationGraphNode,
    CorrelationGraphEdge,
    CorrelationGraphDTO,
    CorrelationSummaryResponse,
    IOCSearchResultDTO,
    STIX21BundleDTO,
)

# STIX namespace UUID for deterministic observable identifiers
SMS_STIX_NAMESPACE = uuid.UUID("a7b3c2d1-e4f5-4678-9abc-def012345678")


# ---------------------------------------------------------------------------
# Normalization Helper Functions
# ---------------------------------------------------------------------------
def normalize_ip(value: str) -> Optional[str]:
    """Validates and canonically formats IPv4 or IPv6 addresses."""
    if not value or not isinstance(value, str):
        return None
    cleaned = value.strip().strip("[]")
    if ":" in cleaned and not cleaned.startswith("[") and "." in cleaned:
        # Possible ip:port
        parts = cleaned.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            cleaned = parts[0]
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        return str(ip_obj)
    except ValueError:
        return None


def normalize_domain_or_hostname(value: str) -> Optional[Tuple[str, IOCType]]:
    """Validates and normalizes domain or hostname string."""
    if not value or not isinstance(value, str):
        return None
    cleaned = value.strip().rstrip(".").lower()
    if not cleaned or len(cleaned) > 253 or " " in cleaned or "/" in cleaned:
        return None
    # Check if pure IP
    try:
        ipaddress.ip_address(cleaned)
        return None
    except ValueError:
        pass

    # Regex for valid hostname / domain
    hostname_regex = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    if hostname_regex.match(cleaned):
        parts = cleaned.split(".")
        if len(parts) == 2:
            return cleaned, IOCType.DOMAIN
        return cleaned, IOCType.HOSTNAME
    return None


def normalize_email_address(value: str) -> Optional[str]:
    """Strips delimiters and validates RFC 5322 email address."""
    if not value or not isinstance(value, str):
        return None
    cleaned = value.strip().strip("<>\"'").lower()
    if "@" not in cleaned:
        return None
    parts = cleaned.split("@")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None
    user_part, domain_part = parts
    if " " in user_part or " " in domain_part:
        return None
    domain_norm = normalize_domain_or_hostname(domain_part)
    if not domain_norm:
        return None
    return f"{user_part}@{domain_norm[0]}"


def normalize_sha256_hash(value: str) -> Optional[str]:
    """Validates 64-character hexadecimal SHA-256 hash."""
    if not value or not isinstance(value, str):
        return None
    cleaned = value.strip().lower()
    if len(cleaned) == 64 and all(c in "0123456789abcdef" for c in cleaned):
        return cleaned
    return None


def normalize_cert_fingerprint(value: str) -> Optional[str]:
    """Validates and formats 64-character SHA-256 certificate fingerprint."""
    if not value or not isinstance(value, str):
        return None
    cleaned = value.strip().replace(":", "").replace(" ", "").upper()
    if len(cleaned) == 64 and all(c in "0123456789ABCDEF" for c in cleaned):
        return cleaned
    return None


def normalize_mail_endpoint(ip_str: str, port_str: str) -> Optional[str]:
    """Canonically formats ip:port mail endpoint."""
    ip_norm = normalize_ip(ip_str)
    if not ip_norm:
        return None
    try:
        port = int(port_str)
        if 1 <= port <= 65535:
            return f"{ip_norm}:{port}"
    except (ValueError, TypeError):
        pass
    return None


# ---------------------------------------------------------------------------
# Correlation Engine Service
# ---------------------------------------------------------------------------
class CorrelationService:
    """
    Forensic Cross-Case Correlation & IOC Intelligence Engine.
    Correlates evidence deterministically across analyses, sessions, cases, and artifacts.
    """

    @classmethod
    def extract_iocs_from_analysis(
        cls,
        analysis: Any,
        case_id: Optional[str] = None
    ) -> List[NormalizedIOC]:
        """
        Extracts all verifiable indicators of compromise from an analysis object or dictionary.
        Attaches exact frame, session, and protocol provenance to each indicator.
        """
        if hasattr(analysis, "model_dump"):
            analysis_dict = analysis.model_dump()
        elif isinstance(analysis, dict):
            analysis_dict = analysis
        else:
            analysis_dict = getattr(analysis, "__dict__", {})

        aid = analysis_dict.get("analysis_id", "unknown_analysis")
        analysis_time = analysis_dict.get("analysis_time_utc", datetime.now(timezone.utc).isoformat())
        sessions_data = analysis_dict.get("sessions", [])
        file_name = analysis_dict.get("file_name", "")

        extracted_map: Dict[Tuple[IOCType, str], NormalizedIOC] = {}

        def record_ioc(
            ioc_type: IOCType,
            raw_val: str,
            norm_val: str,
            session_id: Optional[str] = None,
            protocol: Optional[str] = None,
            frame_no: Optional[int] = None,
            source: str = "PCAP_PACKET",
            obs_time: Optional[str] = None,
            findings: Optional[List[str]] = None
        ):
            if not norm_val:
                return
            key = (ioc_type, norm_val)
            prov = IOCProvenance(
                analysis_id=aid,
                case_id=case_id,
                session_id=session_id,
                protocol=protocol,
                frame_number=frame_no,
                evidence_source=source,
                observed_at_utc=obs_time or analysis_time
            )
            if key in extracted_map:
                existing = extracted_map[key]
                existing.provenance.append(prov)
                existing.observation_count += 1
                if findings:
                    for f in findings:
                        if f not in existing.associated_findings:
                            existing.associated_findings.append(f)
            else:
                extracted_map[key] = NormalizedIOC(
                    ioc_type=ioc_type,
                    raw_value=raw_val,
                    normalized_value=norm_val,
                    provenance=[prov],
                    first_seen_utc=obs_time or analysis_time,
                    last_seen_utc=obs_time or analysis_time,
                    observation_count=1,
                    associated_findings=findings or []
                )

        # 1. Process Sessions
        for s in sessions_data:
            s_dict = s if isinstance(s, dict) else (s.model_dump() if hasattr(s, "model_dump") else s.__dict__)
            sid = s_dict.get("session_id")
            proto = s_dict.get("protocol", "SMTP")
            start_iso = s_dict.get("start_time_iso", analysis_time)

            # Extract finding IDs attached to this session
            sec_assess = s_dict.get("security_assessment") or {}
            if hasattr(sec_assess, "__dict__"):
                sec_assess = sec_assess.__dict__
            f_list = sec_assess.get("findings", [])
            session_finding_ids = []
            for f in f_list:
                fid = f.get("id") if isinstance(f, dict) else getattr(f, "id", None)
                if fid:
                    session_finding_ids.append(fid)

            # Client endpoint & IP
            client_raw = s_dict.get("client", "")
            if client_raw:
                c_ip = s_dict.get("client_ip")
                if not c_ip and ":" in client_raw:
                    c_ip = client_raw.rsplit(":", 1)[0]
                norm_c_ip = normalize_ip(c_ip or client_raw)
                if norm_c_ip:
                    record_ioc(IOCType.IP_ADDRESS, client_raw, norm_c_ip, sid, proto, source="PCAP_PACKET", obs_time=start_iso, findings=session_finding_ids)

            # Server endpoint & IP
            server_raw = s_dict.get("server", "")
            if server_raw:
                s_ip = s_dict.get("server_ip")
                s_port = s_dict.get("server_port")
                if not s_ip and ":" in server_raw:
                    parts = server_raw.rsplit(":", 1)
                    s_ip = parts[0]
                    if not s_port and len(parts) > 1 and parts[1].isdigit():
                        s_port = int(parts[1])
                norm_s_ip = normalize_ip(s_ip or server_raw)
                if norm_s_ip:
                    record_ioc(IOCType.IP_ADDRESS, server_raw, norm_s_ip, sid, proto, source="PCAP_PACKET", obs_time=start_iso, findings=session_finding_ids)
                    if s_port:
                        endpoint = normalize_mail_endpoint(norm_s_ip, str(s_port))
                        if endpoint:
                            record_ioc(IOCType.MAIL_ENDPOINT, f"{server_raw}:{s_port}", endpoint, sid, proto, source="PCAP_PACKET", obs_time=start_iso, findings=session_finding_ids)

            # Server Hostname and Root Domain
            hostname_raw = s_dict.get("server_hostname")
            if hostname_raw:
                norm_host_tuple = normalize_domain_or_hostname(hostname_raw)
                if norm_host_tuple:
                    norm_val, ioc_t = norm_host_tuple
                    record_ioc(ioc_t, hostname_raw, norm_val, sid, proto, source="PCAP_PACKET", obs_time=start_iso, findings=session_finding_ids)
                    # Extract root domain if hostname is a subdomain
                    parts = norm_val.split(".")
                    if len(parts) > 2:
                        root_domain = ".".join(parts[-2:])
                        record_ioc(IOCType.DOMAIN, hostname_raw, root_domain, sid, proto, source="PCAP_PACKET", obs_time=start_iso, findings=session_finding_ids)

            # TLS Metadata
            tls_data = s_dict.get("tls") or {}
            if hasattr(tls_data, "__dict__"):
                tls_data = tls_data.__dict__

            if tls_data:
                cert_details = tls_data.get("certificate_details") or s_dict.get("certificate_details") or {}
                if hasattr(cert_details, "__dict__"):
                    cert_details = cert_details.__dict__

                # Certificate fingerprint
                cert_fp = tls_data.get("certificate_fingerprint_sha256") or tls_data.get("cert_sha256") or cert_details.get("certificate_fingerprint_sha256")
                if cert_fp:
                    norm_fp = normalize_cert_fingerprint(cert_fp)
                    if norm_fp:
                        record_ioc(IOCType.CERTIFICATE_FINGERPRINT, cert_fp, norm_fp, sid, proto, source="TLS_CERTIFICATE", obs_time=start_iso, findings=session_finding_ids)

                # Certificate subject / issuer
                cert_subj = tls_data.get("certificate_subject") or tls_data.get("cert_subject") or cert_details.get("subject")
                if cert_subj and isinstance(cert_subj, str) and cert_subj.strip():
                    record_ioc(IOCType.CERTIFICATE_SUBJECT, cert_subj, cert_subj.strip(), sid, proto, source="TLS_CERTIFICATE", obs_time=start_iso, findings=session_finding_ids)

                cert_issuer = tls_data.get("certificate_issuer") or tls_data.get("cert_issuer") or cert_details.get("issuer")
                if cert_issuer and isinstance(cert_issuer, str) and cert_issuer.strip():
                    record_ioc(IOCType.CERTIFICATE_ISSUER, cert_issuer, cert_issuer.strip(), sid, proto, source="TLS_CERTIFICATE", obs_time=start_iso, findings=session_finding_ids)

                # TLS Configuration String
                ver = tls_data.get("negotiated_version")
                cipher = tls_data.get("cipher_name")
                pfs = tls_data.get("pfs_status")
                if ver and cipher:
                    tls_conf = f"{ver}:{cipher}"
                    if pfs:
                        tls_conf += f":{pfs}"
                    record_ioc(IOCType.TLS_CONFIGURATION, tls_conf, tls_conf, sid, proto, source="TLS_HANDSHAKE", obs_time=start_iso, findings=session_finding_ids)

            # EML Message Details if embedded in session
            eml_data = s_dict.get("eml_forensics") or s_dict.get("email_metadata") or {}
            if hasattr(eml_data, "__dict__"):
                eml_data = eml_data.__dict__
            if eml_data:
                for field_name in ["from_address", "to_address", "return_path"]:
                    val = eml_data.get(field_name)
                    if val:
                        norm_email = normalize_email_address(val)
                        if norm_email:
                            record_ioc(IOCType.EMAIL_ADDRESS, val, norm_email, sid, proto, source="EML_HEADER", obs_time=start_iso, findings=session_finding_ids)
                            domain_part = norm_email.split("@")[1]
                            raw_dom = val.split("@")[1] if "@" in val else val
                            record_ioc(IOCType.DOMAIN, raw_dom, domain_part, sid, proto, source="EML_HEADER", obs_time=start_iso, findings=session_finding_ids)

                msg_id = eml_data.get("message_id")
                if msg_id and isinstance(msg_id, str) and msg_id.strip():
                    clean_msg_id = msg_id.strip().strip("<>")
                    record_ioc(IOCType.MESSAGE_ID, msg_id, clean_msg_id, sid, proto, source="EML_HEADER", obs_time=start_iso, findings=session_finding_ids)

        return list(extracted_map.values())

    @classmethod
    def get_all_corpus_iocs(cls, db_path: Optional[str] = None) -> List[NormalizedIOC]:
        """
        Extracts and aggregates normalized IOCs across all analyses and cases in the repository.
        """
        all_cases = ForensicRepository.list_cases(include_archived=True, db_path=db_path)
        case_by_analysis: Dict[str, str] = {}
        for c in all_cases:
            cid = c.get("id")
            for aid in c.get("analysis_ids", []):
                case_by_analysis[aid] = cid

        all_analyses = ForensicRepository.list_analyses(include_archived=True, db_path=db_path)
        global_iocs: Dict[Tuple[IOCType, str], NormalizedIOC] = {}

        for a_summary in all_analyses:
            aid = a_summary.get("id") or a_summary.get("analysis_id")
            if not aid:
                continue
            full_analysis = ForensicRepository.get_analysis(aid, db_path=db_path)
            if not full_analysis:
                continue

            case_id = case_by_analysis.get(aid)
            iocs = cls.extract_iocs_from_analysis(full_analysis, case_id=case_id)
            for ioc in iocs:
                key = (ioc.ioc_type, ioc.normalized_value)
                if key in global_iocs:
                    existing = global_iocs[key]
                    existing.provenance.extend(ioc.provenance)
                    existing.observation_count += ioc.observation_count
                    if ioc.first_seen_utc < existing.first_seen_utc:
                        existing.first_seen_utc = ioc.first_seen_utc
                    if ioc.last_seen_utc > existing.last_seen_utc:
                        existing.last_seen_utc = ioc.last_seen_utc
                    for f in ioc.associated_findings:
                        if f not in existing.associated_findings:
                            existing.associated_findings.append(f)
                else:
                    global_iocs[key] = ioc

        # Also inspect case artifacts for SHA-256 hashes
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM case_artifacts ORDER BY added_at ASC")
        art_rows = cursor.fetchall()
        conn.close()

        for r in art_rows:
            h = normalize_sha256_hash(r["sha256"])
            if h:
                key = (IOCType.ARTIFACT_SHA256, h)
                prov = IOCProvenance(
                    analysis_id=r["analysis_id"] or "unlinked_artifact",
                    case_id=r["case_id"],
                    evidence_source="CASE_ARTIFACT",
                    observed_at_utc=r["added_at"]
                )
                if key in global_iocs:
                    global_iocs[key].provenance.append(prov)
                    global_iocs[key].observation_count += 1
                else:
                    global_iocs[key] = NormalizedIOC(
                        ioc_type=IOCType.ARTIFACT_SHA256,
                        raw_value=r["sha256"],
                        normalized_value=h,
                        provenance=[prov],
                        first_seen_utc=r["added_at"],
                        last_seen_utc=r["added_at"],
                        observation_count=1,
                        associated_findings=[]
                    )

        return list(global_iocs.values())

    @classmethod
    def compute_correlations(
        cls,
        db_path: Optional[str] = None
    ) -> List[CorrelationRelationship]:
        """
        Identifies cross-analysis and cross-case evidence correlations from the aggregated IOCs.
        A correlation exists when an indicator appears across >= 2 analyses or >= 2 cases.
        """
        all_iocs = cls.get_all_corpus_iocs(db_path=db_path)
        relationships: List[CorrelationRelationship] = []

        type_to_rel_map = {
            IOCType.IP_ADDRESS: CorrelationRelationshipType.SHARED_IP,
            IOCType.DOMAIN: CorrelationRelationshipType.SHARED_DOMAIN,
            IOCType.HOSTNAME: CorrelationRelationshipType.SHARED_HOSTNAME,
            IOCType.EMAIL_ADDRESS: CorrelationRelationshipType.SHARED_EMAIL,
            IOCType.CERTIFICATE_FINGERPRINT: CorrelationRelationshipType.SHARED_CERTIFICATE,
            IOCType.CERTIFICATE_SUBJECT: CorrelationRelationshipType.SHARED_CERTIFICATE_SUBJECT,
            IOCType.CERTIFICATE_ISSUER: CorrelationRelationshipType.SHARED_CERTIFICATE_ISSUER,
            IOCType.MESSAGE_ID: CorrelationRelationshipType.SHARED_MESSAGE_ID,
            IOCType.ARTIFACT_SHA256: CorrelationRelationshipType.SHARED_ARTIFACT,
            IOCType.MAIL_ENDPOINT: CorrelationRelationshipType.SHARED_MAIL_ENDPOINT,
            IOCType.TLS_CONFIGURATION: CorrelationRelationshipType.SHARED_TLS_CONFIG,
        }

        for ioc in all_iocs:
            matched_analyses = sorted(list(set(p.analysis_id for p in ioc.provenance if p.analysis_id and p.analysis_id != "unlinked_artifact")))
            matched_cases = sorted(list(set(p.case_id for p in ioc.provenance if p.case_id)))

            # Correlation threshold: appears in >= 2 analyses or >= 2 cases
            if len(matched_analyses) >= 2 or len(matched_cases) >= 2:
                rel_type = type_to_rel_map.get(ioc.ioc_type, CorrelationRelationshipType.SHARED_IP)
                rel_id = f"REL-{ioc.ioc_type.value}-{uuid.uuid5(SMS_STIX_NAMESPACE, ioc.normalized_value).hex[:8].upper()}"

                # Explainable summary
                summary_parts = []
                summary_parts.append(f"Observed {ioc.ioc_type.value} '{ioc.normalized_value}' across {len(matched_analyses)} analyses")
                if matched_cases:
                    summary_parts.append(f"and {len(matched_cases)} cases ({', '.join(matched_cases)})")
                protocols = sorted(list(set(p.protocol for p in ioc.provenance if p.protocol)))
                if protocols:
                    summary_parts.append(f"in {'/'.join(protocols)} traffic")

                evidence_summary = " ".join(summary_parts) + "."

                # Risk Context
                risk_context = None
                if ioc.associated_findings:
                    risk_context = f"Associated with security findings: {', '.join(ioc.associated_findings)}"

                relationships.append(CorrelationRelationship(
                    relationship_id=rel_id,
                    relationship_type=rel_type,
                    ioc_type=ioc.ioc_type,
                    ioc_value=ioc.normalized_value,
                    matched_analyses=matched_analyses,
                    matched_cases=matched_cases,
                    observation_count=ioc.observation_count,
                    evidence_summary=evidence_summary,
                    risk_context=risk_context,
                    first_observed_utc=ioc.first_seen_utc,
                    last_observed_utc=ioc.last_seen_utc,
                ))

        # Sort by matched analyses count descending, then observation count
        relationships.sort(key=lambda r: (len(r.matched_analyses), len(r.matched_cases), r.observation_count), reverse=True)
        return relationships

    @classmethod
    def get_correlation_summary(cls, db_path: Optional[str] = None) -> CorrelationSummaryResponse:
        """Computes summary statistics and top correlations across the entire forensic corpus."""
        all_cases = ForensicRepository.list_cases(include_archived=True, db_path=db_path)
        all_analyses = ForensicRepository.list_analyses(include_archived=True, db_path=db_path)
        all_iocs = cls.get_all_corpus_iocs(db_path=db_path)
        relationships = cls.compute_correlations(db_path=db_path)

        breakdown: Dict[str, int] = defaultdict(int)
        for ioc in all_iocs:
            breakdown[ioc.ioc_type.value] += 1

        top_correlated = []
        for r in relationships[:10]:
            top_correlated.append({
                "ioc_type": r.ioc_type.value,
                "ioc_value": r.ioc_value,
                "analysis_count": len(r.matched_analyses),
                "case_count": len(r.matched_cases),
                "observation_count": r.observation_count,
                "risk_context": r.risk_context,
            })

        return CorrelationSummaryResponse(
            total_cases_evaluated=len(all_cases),
            total_analyses_evaluated=len(all_analyses),
            total_unique_iocs=len(all_iocs),
            total_relationships=len(relationships),
            relationships=relationships,
            ioc_breakdown_by_type=dict(breakdown),
            top_correlated_iocs=top_correlated,
        )

    @classmethod
    def build_correlation_graph(
        cls,
        case_id: Optional[str] = None,
        analysis_id: Optional[str] = None,
        ioc_type: Optional[str] = None,
        db_path: Optional[str] = None
    ) -> CorrelationGraphDTO:
        """
        Constructs a deterministic multi-entity correlation graph.
        Nodes represent Cases, Analyses, and Indicators.
        Edges represent evidence-backed associations.
        """
        all_cases = ForensicRepository.list_cases(include_archived=True, db_path=db_path)
        all_iocs = cls.get_all_corpus_iocs(db_path=db_path)
        correlations = cls.compute_correlations(db_path=db_path)
        correlated_ioc_keys = set((c.ioc_type, c.ioc_value) for c in correlations)

        nodes_map: Dict[str, CorrelationGraphNode] = {}
        edges_set: Set[Tuple[str, str, str]] = set()
        edges_list: List[CorrelationGraphEdge] = []

        # Helper to add node
        def add_node(nid: str, ntype: GraphNodeType, label: str, props: Optional[Dict[str, Any]] = None):
            if nid not in nodes_map:
                nodes_map[nid] = CorrelationGraphNode(
                    node_id=nid,
                    node_type=ntype,
                    label=label,
                    properties=props or {}
                )

        # Helper to add edge
        def add_edge(src: str, tgt: str, etype: GraphEdgeType, label: str, props: Optional[Dict[str, Any]] = None):
            edge_key = (src, tgt, etype.value)
            if edge_key not in edges_set:
                edges_set.add(edge_key)
                edges_list.append(CorrelationGraphEdge(
                    source_id=src,
                    target_id=tgt,
                    edge_type=etype,
                    label=label,
                    properties=props or {}
                ))

        ioc_type_to_node_type = {
            IOCType.IP_ADDRESS: GraphNodeType.IP,
            IOCType.DOMAIN: GraphNodeType.DOMAIN,
            IOCType.HOSTNAME: GraphNodeType.HOSTNAME,
            IOCType.EMAIL_ADDRESS: GraphNodeType.EMAIL,
            IOCType.CERTIFICATE_FINGERPRINT: GraphNodeType.CERTIFICATE,
            IOCType.CERTIFICATE_SUBJECT: GraphNodeType.CERTIFICATE,
            IOCType.CERTIFICATE_ISSUER: GraphNodeType.CERTIFICATE,
            IOCType.ARTIFACT_SHA256: GraphNodeType.ARTIFACT,
            IOCType.MAIL_ENDPOINT: GraphNodeType.MAIL_ENDPOINT,
            IOCType.TLS_CONFIGURATION: GraphNodeType.TLS_CONFIG,
            IOCType.MESSAGE_ID: GraphNodeType.EMAIL,
        }

        ioc_type_to_edge_type = {
            IOCType.IP_ADDRESS: GraphEdgeType.ANALYSIS_OBSERVED_IP,
            IOCType.DOMAIN: GraphEdgeType.ANALYSIS_OBSERVED_DOMAIN,
            IOCType.HOSTNAME: GraphEdgeType.ANALYSIS_OBSERVED_HOSTNAME,
            IOCType.EMAIL_ADDRESS: GraphEdgeType.ANALYSIS_OBSERVED_EMAIL,
            IOCType.CERTIFICATE_FINGERPRINT: GraphEdgeType.ANALYSIS_OBSERVED_CERT,
            IOCType.CERTIFICATE_SUBJECT: GraphEdgeType.ANALYSIS_OBSERVED_CERT,
            IOCType.CERTIFICATE_ISSUER: GraphEdgeType.ANALYSIS_OBSERVED_CERT,
            IOCType.ARTIFACT_SHA256: GraphEdgeType.ANALYSIS_PRODUCED_ARTIFACT,
            IOCType.MAIL_ENDPOINT: GraphEdgeType.ANALYSIS_OBSERVED_ENDPOINT,
            IOCType.TLS_CONFIGURATION: GraphEdgeType.ANALYSIS_OBSERVED_TLS_CONFIG,
            IOCType.MESSAGE_ID: GraphEdgeType.ANALYSIS_OBSERVED_EMAIL,
        }

        # 1. Add Case Nodes and Case -> Analysis edges
        for c in all_cases:
            cid = c.get("id")
            if case_id and cid != case_id:
                continue
            c_node_id = f"case:{cid}"
            add_node(c_node_id, GraphNodeType.CASE, c.get("title") or cid, {
                "case_id": cid,
                "status": c.get("status"),
                "analyst_name": c.get("analyst_name"),
            })

            for aid in c.get("analysis_ids", []):
                if analysis_id and aid != analysis_id:
                    continue
                a_node_id = f"analysis:{aid}"
                add_node(a_node_id, GraphNodeType.ANALYSIS, aid, {"analysis_id": aid})
                add_edge(c_node_id, a_node_id, GraphEdgeType.CASE_CONTAINS_ANALYSIS, "contains")

        # 2. Add IOC Nodes and Analysis -> IOC edges
        for ioc in all_iocs:
            if ioc_type and ioc.ioc_type.value != ioc_type:
                continue
            is_correlated = (ioc.ioc_type, ioc.normalized_value) in correlated_ioc_keys
            node_t = ioc_type_to_node_type.get(ioc.ioc_type, GraphNodeType.IP)
            ioc_node_id = f"ioc:{ioc.ioc_type.value}:{ioc.normalized_value}"

            matched_in_filter = False
            for p in ioc.provenance:
                if case_id and p.case_id != case_id:
                    continue
                if analysis_id and p.analysis_id != analysis_id:
                    continue

                matched_in_filter = True
                a_node_id = f"analysis:{p.analysis_id}"
                add_node(a_node_id, GraphNodeType.ANALYSIS, p.analysis_id, {"analysis_id": p.analysis_id})

                edge_t = ioc_type_to_edge_type.get(ioc.ioc_type, GraphEdgeType.ANALYSIS_OBSERVED_IP)
                add_edge(a_node_id, ioc_node_id, edge_t, "observed", {
                    "protocol": p.protocol,
                    "session_id": p.session_id,
                    "frame_number": p.frame_number,
                })

            if matched_in_filter:
                add_node(ioc_node_id, node_t, ioc.normalized_value, {
                    "ioc_type": ioc.ioc_type.value,
                    "raw_value": ioc.raw_value,
                    "observation_count": ioc.observation_count,
                    "is_correlated": is_correlated,
                    "associated_findings": ioc.associated_findings,
                })

        return CorrelationGraphDTO(
            nodes=list(nodes_map.values()),
            edges=edges_list,
            total_nodes=len(nodes_map),
            total_edges=len(edges_list),
        )

    @classmethod
    def search_iocs(
        cls,
        query: str,
        ioc_type: Optional[str] = None,
        db_path: Optional[str] = None
    ) -> IOCSearchResultDTO:
        """
        Searches indicators across the forensic repository by value or substring.
        Returns matching indicators, their correlations, and linked analyses/cases.
        """
        clean_q = query.strip().lower()
        all_iocs = cls.get_all_corpus_iocs(db_path=db_path)
        all_relationships = cls.compute_correlations(db_path=db_path)

        matched_iocs = []
        linked_analyses = set()
        linked_cases = set()

        for ioc in all_iocs:
            if ioc_type and ioc.ioc_type.value != ioc_type:
                continue
            if clean_q in ioc.normalized_value.lower() or clean_q in ioc.raw_value.lower():
                matched_iocs.append(ioc)
                for p in ioc.provenance:
                    if p.analysis_id and p.analysis_id != "unlinked_artifact":
                        linked_analyses.add(p.analysis_id)
                    if p.case_id:
                        linked_cases.add(p.case_id)

        matched_keys = set((i.ioc_type, i.normalized_value) for i in matched_iocs)
        matched_rels = [r for r in all_relationships if (r.ioc_type, r.ioc_value) in matched_keys]

        return IOCSearchResultDTO(
            query=query,
            matched_iocs=matched_iocs,
            correlated_relationships=matched_rels,
            linked_analyses=sorted(list(linked_analyses)),
            linked_cases=sorted(list(linked_cases)),
        )

    @classmethod
    def export_stix21_bundle(
        cls,
        case_id: Optional[str] = None,
        analysis_id: Optional[str] = None,
        db_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generates an offline, compliant STIX 2.1 JSON bundle representing forensic observations,
        cyber observables (SCOs), reports (SDOs), and correlation relationships.
        """
        all_iocs = cls.get_all_corpus_iocs(db_path=db_path)
        relationships = cls.compute_correlations(db_path=db_path)
        all_cases = ForensicRepository.list_cases(include_archived=True, db_path=db_path)
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        stix_objects: List[Dict[str, Any]] = []
        bundle_uuid = str(uuid.uuid4())
        bundle_id = f"bundle--{bundle_uuid}"

        # 1. Generate Identity Object (SecureMailScope X)
        identity_id = f"identity--{uuid.uuid5(SMS_STIX_NAMESPACE, 'SecureMailScope-X-System').hex}"
        identity_obj = {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now_iso,
            "modified": now_iso,
            "name": "SecureMailScope X Forensic Engine",
            "identity_class": "system",
        }
        stix_objects.append(identity_obj)

        # 2. Map Cyber Observables (SCOs)
        sco_ids: Dict[Tuple[IOCType, str], str] = {}
        for ioc in all_iocs:
            if ioc.ioc_type == IOCType.IP_ADDRESS:
                is_v6 = ":" in ioc.normalized_value
                obj_type = "ipv6-addr" if is_v6 else "ipv4-addr"
                sco_id = f"{obj_type}--{uuid.uuid5(SMS_STIX_NAMESPACE, f'{obj_type}:{ioc.normalized_value}').hex}"
                sco_obj = {
                    "type": obj_type,
                    "spec_version": "2.1",
                    "id": sco_id,
                    "value": ioc.normalized_value,
                }
                sco_ids[(ioc.ioc_type, ioc.normalized_value)] = sco_id
                stix_objects.append(sco_obj)

            elif ioc.ioc_type in (IOCType.DOMAIN, IOCType.HOSTNAME):
                sco_id = f"domain-name--{uuid.uuid5(SMS_STIX_NAMESPACE, f'domain:{ioc.normalized_value}').hex}"
                sco_obj = {
                    "type": "domain-name",
                    "spec_version": "2.1",
                    "id": sco_id,
                    "value": ioc.normalized_value,
                }
                sco_ids[(ioc.ioc_type, ioc.normalized_value)] = sco_id
                stix_objects.append(sco_obj)

            elif ioc.ioc_type == IOCType.EMAIL_ADDRESS:
                sco_id = f"email-addr--{uuid.uuid5(SMS_STIX_NAMESPACE, f'email:{ioc.normalized_value}').hex}"
                sco_obj = {
                    "type": "email-addr",
                    "spec_version": "2.1",
                    "id": sco_id,
                    "value": ioc.normalized_value,
                }
                sco_ids[(ioc.ioc_type, ioc.normalized_value)] = sco_id
                stix_objects.append(sco_obj)

            elif ioc.ioc_type == IOCType.CERTIFICATE_FINGERPRINT:
                sco_id = f"x509-certificate--{uuid.uuid5(SMS_STIX_NAMESPACE, f'cert:{ioc.normalized_value}').hex}"
                sco_obj = {
                    "type": "x509-certificate",
                    "spec_version": "2.1",
                    "id": sco_id,
                    "hashes": {
                        "SHA-256": ioc.normalized_value
                    }
                }
                sco_ids[(ioc.ioc_type, ioc.normalized_value)] = sco_id
                stix_objects.append(sco_obj)

            elif ioc.ioc_type == IOCType.ARTIFACT_SHA256:
                sco_id = f"file--{uuid.uuid5(SMS_STIX_NAMESPACE, f'file:{ioc.normalized_value}').hex}"
                sco_obj = {
                    "type": "file",
                    "spec_version": "2.1",
                    "id": sco_id,
                    "hashes": {
                        "SHA-256": ioc.normalized_value
                    }
                }
                sco_ids[(ioc.ioc_type, ioc.normalized_value)] = sco_id
                stix_objects.append(sco_obj)

            elif ioc.ioc_type == IOCType.MAIL_ENDPOINT:
                parts = ioc.normalized_value.split(":")
                if len(parts) == 2 and parts[1].isdigit():
                    sco_id = f"network-traffic--{uuid.uuid5(SMS_STIX_NAMESPACE, f'traffic:{ioc.normalized_value}').hex}"
                    sco_obj = {
                        "type": "network-traffic",
                        "spec_version": "2.1",
                        "id": sco_id,
                        "dst_port": int(parts[1]),
                        "protocols": ["tcp", "smtp"],
                    }
                    sco_ids[(ioc.ioc_type, ioc.normalized_value)] = sco_id
                    stix_objects.append(sco_obj)

        # 3. Generate STIX Reports (SDOs) for Cases
        for c in all_cases:
            cid = c.get("id")
            if case_id and cid != case_id:
                continue
            rep_id = f"report--{uuid.uuid5(SMS_STIX_NAMESPACE, f'case:{cid}').hex}"
            obs_refs = []
            for ioc in all_iocs:
                for p in ioc.provenance:
                    if p.case_id == cid or p.analysis_id in c.get("analysis_ids", []):
                        sco_id = sco_ids.get((ioc.ioc_type, ioc.normalized_value))
                        if sco_id and sco_id not in obs_refs:
                            obs_refs.append(sco_id)

            rep_obj = {
                "type": "report",
                "spec_version": "2.1",
                "id": rep_id,
                "created_by_ref": identity_id,
                "created": now_iso,
                "modified": now_iso,
                "name": f"Forensic Case Report: {c.get('title', cid)}",
                "description": c.get("description", "SecureMailScope X Case Investigation"),
                "report_types": ["investigation"],
                "published": now_iso,
                "object_refs": [identity_id] + obs_refs,
            }
            stix_objects.append(rep_obj)

        # 4. Generate STIX Relationships for correlated indicators
        for rel in relationships:
            sco_id = sco_ids.get((rel.ioc_type, rel.ioc_value))
            if not sco_id:
                continue
            rel_obj_id = f"relationship--{uuid.uuid5(SMS_STIX_NAMESPACE, f'rel:{rel.relationship_id}').hex}"
            stix_rel = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_obj_id,
                "created_by_ref": identity_id,
                "created": now_iso,
                "modified": now_iso,
                "relationship_type": "related-to",
                "source_ref": sco_id,
                "target_ref": identity_id,
                "description": rel.evidence_summary,
            }
            stix_objects.append(stix_rel)

        return {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": stix_objects,
        }
