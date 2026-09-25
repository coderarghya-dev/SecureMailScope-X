"""
SecureMailScope X - DNS & Email Domain Authentication Analyzer
Analyzes SPF, DKIM, DMARC, MTA-STS, BIMI, and DANE policies.
CRITICAL FORENSIC BOUNDARY: This module is strictly separated from passive PCAP analysis
and only executes active network DNS lookups when explicitly requested by an analyst.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from app.schemas.forensic import (
    AuthProvenanceSource,
    HistoricalApplicability,
    DNSAuthStatus,
    DomainAuthenticationAssessment
)
from app.dns.dns_auth_analyzer import DNSAuthAnalyzer
from app.dns.dns_resolver import DNSResolver


@dataclass
class DomainAuthAssessment:
    domain: str
    query_timestamp_iso: str
    is_active_lookup: bool
    data_source: str
    spf_record: Optional[str] = None
    spf_policy: Optional[str] = None
    dmarc_record: Optional[str] = None
    dmarc_policy: Optional[str] = None
    dmarc_pct: Optional[int] = 100
    mta_sts_record: Optional[str] = None
    mta_sts_mode: Optional[str] = None
    bimi_record: Optional[str] = None
    dane_tlsa_record: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    overall_auth_posture: str = "UNKNOWN"
    assessment_model: Optional[DomainAuthenticationAssessment] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "query_timestamp_iso": self.query_timestamp_iso,
            "is_active_lookup": self.is_active_lookup,
            "data_source": self.data_source,
            "spf_record": self.spf_record,
            "spf_policy": self.spf_policy,
            "dmarc_record": self.dmarc_record,
            "dmarc_policy": self.dmarc_policy,
            "dmarc_pct": self.dmarc_pct,
            "mta_sts_record": self.mta_sts_record,
            "mta_sts_mode": self.mta_sts_mode,
            "bimi_record": self.bimi_record,
            "dane_tlsa_record": self.dane_tlsa_record,
            "findings": self.findings,
            "overall_auth_posture": self.overall_auth_posture,
        }


class EmailAuthAnalyzer:
    """Evaluates Domain Email Authentication & Security Policies (SPF, DMARC, MTA-STS, BIMI, DANE)."""

    @classmethod
    def analyze_records(
        cls,
        domain: str,
        txt_records: List[str],
        dmarc_txt: Optional[str] = None,
        mta_sts_txt: Optional[str] = None,
        bimi_txt: Optional[str] = None,
        tlsa_records: Optional[List[str]] = None,
        is_active: bool = False,
        data_source: str = "Offline Record Evaluation",
    ) -> DomainAuthAssessment:
        assessment = DNSAuthAnalyzer.evaluate_provided_records(
            domain=domain,
            txt_records=txt_records,
            dmarc_txt=dmarc_txt,
            mta_sts_txt=mta_sts_txt,
            bimi_txt=bimi_txt,
            tlsa_records=tlsa_records
        )
        if is_active:
            assessment.source = AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT
            assessment.historical_applicability = HistoricalApplicability.CURRENT_STATE_ONLY
            assessment.is_active_enrichment = True

        findings: List[Dict[str, Any]] = []
        if assessment.spf.policy_qualifier == "+all":
            findings.append({
                "id": "FINDING-SPF-ALLOW-ALL",
                "title": "Insecure SPF Configuration: +all Allows Spoofing",
                "severity": "CRITICAL",
                "description": "The SPF record ends with '+all', explicitly authorizing any mail server to send as this domain.",
                "recommendation": "Remove '+all' immediately and configure '-all'."
            })
        elif assessment.spf.policy_qualifier == "?all":
            findings.append({
                "id": "FINDING-SPF-NEUTRAL",
                "title": "SPF Policy Uses Permissive Neutral Rule (?all)",
                "severity": "MEDIUM",
                "description": "The SPF record ends with '?all', which provides no enforcement against spoofing.",
                "recommendation": "Transition SPF record to strict fail '-all' or softfail '~all'."
            })
        elif not assessment.spf.spf_policy_present:
            findings.append({
                "id": "FINDING-SPF-MISSING",
                "title": "Missing SPF Record",
                "severity": "HIGH",
                "description": f"Domain {domain} does not publish an SPF record.",
                "recommendation": "Publish a valid TXT SPF record."
            })

        if assessment.dmarc.policy_p == "none":
            findings.append({
                "id": "FINDING-DMARC-POLICY-NONE",
                "title": "Weak DMARC Policy (p=none)",
                "severity": "MEDIUM",
                "description": "DMARC policy is set to 'p=none' (monitoring only).",
                "recommendation": "Upgrade DMARC policy to 'p=quarantine' or 'p=reject'."
            })
        elif not assessment.dmarc.raw_record:
            findings.append({
                "id": "FINDING-DMARC-MISSING",
                "title": "Missing DMARC Policy Record",
                "severity": "HIGH",
                "description": f"Domain {domain} has no _dmarc TXT record.",
                "recommendation": "Publish a DMARC record at _dmarc.{domain}."
            })

        if assessment.spf.policy_qualifier == "-all":
            spf_policy_str = "PASS_RESTRICTIVE (-all)"
        elif assessment.spf.policy_qualifier == "~all":
            spf_policy_str = "SOFTFAIL (~all)"
        elif assessment.spf.policy_qualifier == "?all":
            spf_policy_str = "NEUTRAL (?all)"
        elif assessment.spf.policy_qualifier == "+all":
            spf_policy_str = "INSECURE (+all)"
        elif not assessment.spf.spf_policy_present:
            spf_policy_str = "MISSING"
        else:
            spf_policy_str = "PRESENT"

        dmarc_policy_str = assessment.dmarc.policy_p if assessment.dmarc.raw_record else "MISSING"

        if mta_sts_txt and ("mode=enforce" in mta_sts_txt.lower() or "mode: enforce" in mta_sts_txt.lower()):
            mta_sts_mode_str = "ENFORCE"
        elif mta_sts_txt and ("mode=testing" in mta_sts_txt.lower() or "mode: testing" in mta_sts_txt.lower()):
            mta_sts_mode_str = "TESTING"
        elif assessment.mta_sts.policy_mode:
            mta_sts_mode_str = assessment.mta_sts.policy_mode.upper()
        elif assessment.mta_sts.raw_record:
            mta_sts_mode_str = "PRESENT"
        else:
            mta_sts_mode_str = "MISSING"

        return DomainAuthAssessment(
            domain=domain,
            query_timestamp_iso=assessment.queried_at_utc or datetime.now(timezone.utc).isoformat(),
            is_active_lookup=is_active,
            data_source=data_source,
            spf_record=assessment.spf.raw_record,
            spf_policy=spf_policy_str,
            dmarc_record=assessment.dmarc.raw_record,
            dmarc_policy=dmarc_policy_str,
            dmarc_pct=assessment.dmarc.percentage_pct,
            mta_sts_record=assessment.mta_sts.raw_record,
            mta_sts_mode=mta_sts_mode_str,
            bimi_record=assessment.bimi.raw_record,
            dane_tlsa_record="; ".join(assessment.dane.tlsa_records) if assessment.dane.tlsa_records else None,
            findings=findings,
            overall_auth_posture=assessment.overall_auth_posture,
            assessment_model=assessment
        )

    @classmethod
    def query_active_domain(cls, domain: str) -> DomainAuthAssessment:
        """Performs explicit active DNS-over-HTTPS query for domain auth records."""
        clean_domain = domain.strip().lower()
        resolver = DNSResolver(timeout_sec=3.0)
        assessment = DNSAuthAnalyzer.evaluate_active_domain(clean_domain, resolver=resolver)

        findings: List[Dict[str, Any]] = []
        if assessment.spf.policy_qualifier == "+all":
            findings.append({
                "id": "FINDING-SPF-ALLOW-ALL",
                "title": "Insecure SPF Configuration: +all Allows Spoofing",
                "severity": "CRITICAL",
                "description": "The SPF record ends with '+all', explicitly authorizing any mail server to send as this domain.",
                "recommendation": "Remove '+all' immediately and configure '-all'."
            })
        elif assessment.spf.policy_qualifier == "?all":
            findings.append({
                "id": "FINDING-SPF-NEUTRAL",
                "title": "SPF Policy Uses Permissive Neutral Rule (?all)",
                "severity": "MEDIUM",
                "description": "The SPF record ends with '?all', which provides no enforcement against spoofing.",
                "recommendation": "Transition SPF record to strict fail '-all' or softfail '~all'."
            })
        elif not assessment.spf.spf_policy_present:
            findings.append({
                "id": "FINDING-SPF-MISSING",
                "title": "Missing SPF Record",
                "severity": "HIGH",
                "description": f"Domain {clean_domain} does not publish an SPF record.",
                "recommendation": "Publish a valid TXT SPF record."
            })

        if assessment.dmarc.policy_p == "none":
            findings.append({
                "id": "FINDING-DMARC-POLICY-NONE",
                "title": "Weak DMARC Policy (p=none)",
                "severity": "MEDIUM",
                "description": "DMARC policy is set to 'p=none' (monitoring only).",
                "recommendation": "Upgrade DMARC policy to 'p=quarantine' or 'p=reject'."
            })
        elif not assessment.dmarc.raw_record:
            findings.append({
                "id": "FINDING-DMARC-MISSING",
                "title": "Missing DMARC Policy Record",
                "severity": "HIGH",
                "description": f"Domain {clean_domain} has no _dmarc TXT record.",
                "recommendation": "Publish a DMARC record at _dmarc.{clean_domain}."
            })

        spf_policy_str = assessment.spf.policy_qualifier or ("PRESENT" if assessment.spf.spf_policy_present else "MISSING")
        dmarc_policy_str = assessment.dmarc.policy_p or "MISSING"
        mta_sts_mode_str = assessment.mta_sts.policy_mode or ("PRESENT" if assessment.mta_sts.raw_record else "MISSING")

        return DomainAuthAssessment(
            domain=clean_domain,
            query_timestamp_iso=assessment.queried_at_utc or datetime.now(timezone.utc).isoformat(),
            is_active_lookup=True,
            data_source="Active DNS-over-HTTPS Lookup (1.1.1.1)",
            spf_record=assessment.spf.raw_record,
            spf_policy=spf_policy_str,
            dmarc_record=assessment.dmarc.raw_record,
            dmarc_policy=dmarc_policy_str,
            dmarc_pct=assessment.dmarc.percentage_pct,
            mta_sts_record=assessment.mta_sts.raw_record,
            mta_sts_mode=mta_sts_mode_str,
            bimi_record=assessment.bimi.raw_record,
            dane_tlsa_record="; ".join(assessment.dane.tlsa_records) if assessment.dane.tlsa_records else None,
            findings=findings,
            overall_auth_posture=assessment.overall_auth_posture,
            assessment_model=assessment
        )
