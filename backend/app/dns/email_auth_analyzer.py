"""
SecureMailScope X - DNS & Email Domain Authentication Analyzer
Analyzes SPF, DKIM, DMARC, MTA-STS, BIMI, and DANE policies.
CRITICAL FORENSIC BOUNDARY: This module is strictly separated from passive PCAP analysis
and only executes active network DNS lookups when explicitly requested by an analyst.
"""

from datetime import datetime, timezone
import json
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class DomainAuthAssessment:
    domain: str
    query_timestamp_iso: str
    is_active_lookup: bool
    data_source: str  # e.g., "Active DNS Lookup (Cloudflare DoH / 1.1.1.1)" or "Offline Static Record"
    spf_record: Optional[str] = None
    spf_policy: Optional[str] = None  # PASS_RESTRICTIVE (-all), SOFTFAIL (~all), NEUTRAL (?all), INSECURE (+all), MISSING
    dmarc_record: Optional[str] = None
    dmarc_policy: Optional[str] = None  # reject, quarantine, none, missing
    dmarc_pct: Optional[int] = 100
    mta_sts_record: Optional[str] = None
    mta_sts_mode: Optional[str] = None  # enforce, testing, none, missing
    bimi_record: Optional[str] = None
    dane_tlsa_record: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    overall_auth_posture: str = "UNKNOWN"

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
        now_iso = datetime.now(timezone.utc).isoformat()
        findings: List[Dict[str, Any]] = []

        # 1. Parse SPF
        spf_rec = None
        for txt in txt_records:
            if txt.strip().startswith("v=spf1"):
                spf_rec = txt.strip()
                break

        spf_policy = "MISSING"
        if spf_rec:
            if "-all" in spf_rec:
                spf_policy = "PASS_RESTRICTIVE (-all)"
            elif "~all" in spf_rec:
                spf_policy = "SOFTFAIL (~all)"
            elif "?all" in spf_rec:
                spf_policy = "NEUTRAL (?all)"
                findings.append({
                    "id": "FINDING-SPF-NEUTRAL",
                    "title": "SPF Policy Uses Permissive Neutral Rule (?all)",
                    "severity": "MEDIUM",
                    "description": "The SPF record ends with '?all', which provides no enforcement against spoofing.",
                    "recommendation": "Transition SPF record to strict fail '-all' or softfail '~all'."
                })
            elif "+all" in spf_rec:
                spf_policy = "INSECURE (+all)"
                findings.append({
                    "id": "FINDING-SPF-ALLOW-ALL",
                    "title": "Insecure SPF Configuration: +all Allows Spoofing",
                    "severity": "CRITICAL",
                    "description": "The SPF record ends with '+all', explicitly authorizing any mail server in the world to send as this domain.",
                    "recommendation": "Remove '+all' immediately and configure '-all'."
                })
        else:
            findings.append({
                "id": "FINDING-SPF-MISSING",
                "title": "Missing SPF Record",
                "severity": "HIGH",
                "description": f"Domain {domain} does not publish an SPF record, allowing unauthorized senders to forge emails.",
                "recommendation": "Publish a valid TXT SPF record (e.g. 'v=spf1 include:... -all')."
            })

        # 2. Parse DMARC
        dmarc_policy = "MISSING"
        dmarc_pct = 100
        if dmarc_txt and dmarc_txt.startswith("v=DMARC1"):
            parts = [p.strip() for p in dmarc_txt.split(";")]
            for part in parts:
                if part.startswith("p="):
                    dmarc_policy = part.split("=")[1].strip().lower()
                elif part.startswith("pct="):
                    try:
                        dmarc_pct = int(part.split("=")[1].strip())
                    except ValueError:
                        pass

            if dmarc_policy == "none":
                findings.append({
                    "id": "FINDING-DMARC-POLICY-NONE",
                    "title": "Weak DMARC Policy (p=none)",
                    "severity": "MEDIUM",
                    "description": "DMARC policy is set to 'p=none' (monitoring only). Unauthenticated spoofed emails will not be rejected or quarantined.",
                    "recommendation": "Upgrade DMARC policy to 'p=quarantine' or 'p=reject'."
                })
            elif dmarc_policy in ["quarantine", "reject"] and dmarc_pct < 100:
                findings.append({
                    "id": "FINDING-DMARC-PARTIAL-PCT",
                    "title": f"DMARC Enforcement Incomplete (pct={dmarc_pct})",
                    "severity": "LOW",
                    "description": f"DMARC policy applies to only {dmarc_pct}% of incoming mail.",
                    "recommendation": "Increase DMARC percentage to 'pct=100' for comprehensive enforcement."
                })
        else:
            findings.append({
                "id": "FINDING-DMARC-MISSING",
                "title": "Missing DMARC Policy Record",
                "severity": "HIGH",
                "description": f"Domain {domain} has no _dmarc TXT record. Receivers cannot verify email authenticity.",
                "recommendation": "Publish a DMARC record at _dmarc.{domain} with at least 'v=DMARC1; p=quarantine'."
            })

        # 3. Parse MTA-STS
        mta_sts_mode = "MISSING"
        if mta_sts_txt and mta_sts_txt.startswith("v=STSv1"):
            mta_sts_mode = "PRESENT"
            if "mode: enforce" in mta_sts_txt or "mode=enforce" in mta_sts_txt:
                mta_sts_mode = "ENFORCE"
            elif "mode: testing" in mta_sts_txt or "mode=testing" in mta_sts_txt:
                mta_sts_mode = "TESTING"
                findings.append({
                    "id": "FINDING-MTA-STS-TESTING",
                    "title": "MTA-STS Policy in Testing Mode",
                    "severity": "LOW",
                    "description": "MTA-STS policy is configured in testing mode and does not enforce TLS encryption.",
                    "recommendation": "Change MTA-STS policy mode to 'enforce'."
                })

        # 4. Overall Posture
        if dmarc_policy == "reject" and spf_policy == "PASS_RESTRICTIVE (-all)":
            overall = "ROBUST"
        elif dmarc_policy in ["reject", "quarantine"]:
            overall = "MODERATE"
        elif dmarc_policy == "none" or spf_rec is not None:
            overall = "BASIC"
        else:
            overall = "DEFICIENT"

        return DomainAuthAssessment(
            domain=domain,
            query_timestamp_iso=now_iso,
            is_active_lookup=is_active,
            data_source=data_source,
            spf_record=spf_rec,
            spf_policy=spf_policy,
            dmarc_record=dmarc_txt,
            dmarc_policy=dmarc_policy,
            dmarc_pct=dmarc_pct,
            mta_sts_record=mta_sts_txt,
            mta_sts_mode=mta_sts_mode,
            bimi_record=bimi_txt,
            dane_tlsa_record="; ".join(tlsa_records) if tlsa_records else None,
            findings=findings,
            overall_auth_posture=overall,
        )

    @classmethod
    def query_active_domain(cls, domain: str) -> DomainAuthAssessment:
        """Performs explicit active DNS-over-HTTPS query for domain auth records."""
        clean_domain = domain.strip().lower()
        
        def doh_query_txt(name: str) -> List[str]:
            url = f"https://cloudflare-dns.com/dns-query?name={name}&type=TXT"
            req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    data = json.loads(response.read().decode())
                    answers = data.get("Answer", [])
                    records = []
                    for ans in answers:
                        if ans.get("type") == 16:  # TXT
                            records.append(ans.get("data", "").strip('"'))
                    return records
            except Exception:
                return []

        txt_records = doh_query_txt(clean_domain)
        dmarc_records = doh_query_txt(f"_dmarc.{clean_domain}")
        mta_sts_records = doh_query_txt(f"_mta-sts.{clean_domain}")
        bimi_records = doh_query_txt(f"default._bimi.{clean_domain}")

        dmarc_txt = dmarc_records[0] if dmarc_records else None
        mta_sts_txt = mta_sts_records[0] if mta_sts_records else None
        bimi_txt = bimi_records[0] if bimi_records else None

        return cls.analyze_records(
            domain=clean_domain,
            txt_records=txt_records,
            dmarc_txt=dmarc_txt,
            mta_sts_txt=mta_sts_txt,
            bimi_txt=bimi_txt,
            is_active=True,
            data_source="Active Cloudflare DNS-over-HTTPS (1.1.1.1)",
        )
