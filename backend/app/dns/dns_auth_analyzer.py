"""
SecureMailScope X - Evidence-Bounded DNS & Domain Authentication Analyzer (Phase 7 / 7.5)
Evaluates SPF, DKIM, DMARC, MTA-STS, BIMI, and DANE policies with strict separation between
passive capture facts and active network enrichment.

Forensic Rules & Provenance Boundaries:
1. Never present live DNS results as packet-capture evidence.
2. Passive analysis is authoritative for captured frames; missing DNS records remain NOT_OBSERVED.
3. Active DNS enrichment is strictly opt-in, timestamped, and labeled CURRENT_STATE_ONLY.
4. Top-level SPF mechanism counting is labeled ESTIMATED; lookup_limit_exceeded is True ONLY
   when verified recursive evaluation proves >10 DNS-query-causing terms.
5. Network timeouts and lookup failures result in status UNAVAILABLE, NEVER false POLICY_ABSENT findings.
6. DKIM signatures observed in headers remain NOT_VERIFIED unless actual crypto verification occurs.
7. DMARC message-level result remains NOT_EVALUATED without verified SPF/DKIM alignment.
8. BIMI presence never implies VMC validation (vmc_validation_status remains NOT_VALIDATED).
9. DANE TLSA records remain dnssec_status = NOT_VALIDATED unless real DNSSEC validation occurs.
"""

from typing import Optional, List, Dict, Any, Tuple, Set
from datetime import datetime, timezone
import re

from app.schemas.forensic import (
    AuthProvenanceSource,
    HistoricalApplicability,
    DNSAuthStatus,
    SPFRecordDetails,
    DKIMRecordDetails,
    DMARCRecordDetails,
    MTASTSRecordDetails,
    BIMIRecordDetails,
    DANERecordDetails,
    DomainAuthenticationAssessment,
    EmailSession
)
from app.dns.dns_resolver import DNSResolver


class DNSAuthAnalyzer:
    """Forensic analyzer for domain email authentication (SPF, DKIM, DMARC, MTA-STS, BIMI, DANE)."""

    # -----------------------------------------------------------------------
    # 1. SPF Parsing & Assessment
    # -----------------------------------------------------------------------
    @classmethod
    def parse_spf_record(
        cls,
        txt_records: List[str],
        provenance: AuthProvenanceSource = AuthProvenanceSource.PASSIVE_CAPTURE,
        historical_applicability: HistoricalApplicability = HistoricalApplicability.UNKNOWN,
        resolver: Optional[DNSResolver] = None,
        recursive: bool = False,
        seen_domains: Optional[Set[str]] = None,
        current_lookups: int = 0
    ) -> SPFRecordDetails:
        """
        Parses SPF TXT records per RFC 7208.
        Lookup accounting:
        - If recursive evaluation is performed with resolver: lookup_count_status = "VERIFIED"
        - If only top-level textual mechanisms are counted: lookup_count_status = "ESTIMATED"
        - If passive / not evaluated: lookup_count_status = "NOT_EVALUATED"
        """
        spf_records = [t.strip() for t in txt_records if t.strip().startswith("v=spf1")]

        if not spf_records:
            status = (
                DNSAuthStatus.NOT_OBSERVED
                if provenance == AuthProvenanceSource.PASSIVE_CAPTURE
                else DNSAuthStatus.UNAVAILABLE
            )
            return SPFRecordDetails(
                status=status,
                lookup_count=0,
                lookup_count_status="NOT_EVALUATED",
                lookup_limit_exceeded=None,
                lookup_limit_risk=None,
                spf_policy_present=False,
                analysis_limitations=["No SPF (v=spf1) TXT record was observed."]
            )

        # Check for multiple SPF records (RFC 7208 Section 3.2 violation)
        if len(spf_records) > 1:
            return SPFRecordDetails(
                status=DNSAuthStatus.INVALID,
                raw_record="; ".join(spf_records),
                version="spf1",
                syntax_valid=False,
                syntax_error="Multiple SPF records published for domain (RFC 7208 Section 3.2 violation).",
                lookup_count=0,
                lookup_count_status="NOT_EVALUATED",
                lookup_limit_exceeded=None,
                lookup_limit_risk=None,
                spf_policy_present=True,
                analysis_limitations=["Multiple SPF records invalidate domain SPF policy per RFC 7208."]
            )

        raw_spf = spf_records[0]
        terms = raw_spf.split()
        version = terms[0] if terms else "v=spf1"
        mechanisms: List[str] = []
        include_domains: List[str] = []
        redirect_domain: Optional[str] = None
        qualifier: Optional[str] = None
        top_level_lookups = 0

        for term in terms[1:]:
            term_clean = term.strip()
            mechanisms.append(term_clean)

            # Check for qualifiers on 'all'
            if term_clean.endswith("all"):
                if term_clean.startswith(("-", "~", "?", "+")):
                    qualifier = term_clean
                elif term_clean == "all":
                    qualifier = "+all"  # Default qualifier in SPF

            # Extract include domains and lookup mechanisms
            if term_clean.startswith("include:"):
                inc = term_clean.split(":", 1)[1].strip()
                if inc:
                    include_domains.append(inc)
                top_level_lookups += 1
            elif term_clean.startswith("redirect="):
                redir = term_clean.split("=", 1)[1].strip()
                if redir:
                    redirect_domain = redir
                top_level_lookups += 1
            elif (
                term_clean.startswith(("a:", "a/", "a"))
                or term_clean.startswith(("mx:", "mx/", "mx"))
                or term_clean.startswith("exists:")
                or term_clean.startswith("ptr")
            ):
                top_level_lookups += 1

        total_lookups = current_lookups + top_level_lookups
        limitations: List[str] = []

        # Recursive evaluation if resolver is provided and enabled
        if recursive and resolver is not None:
            visited = set(seen_domains) if seen_domains else set()
            lookup_count_status = "VERIFIED"
            
            # Follow includes up to 10 total lookups or recursion depth
            for inc_dom in include_domains:
                if inc_dom.lower() in visited:
                    continue
                visited.add(inc_dom.lower())
                nested_txt, success, _ = resolver.query_txt_with_status(inc_dom)
                if success and nested_txt:
                    nested_res = cls.parse_spf_record(
                        nested_txt,
                        provenance=provenance,
                        historical_applicability=historical_applicability,
                        resolver=resolver,
                        recursive=True,
                        seen_domains=visited,
                        current_lookups=total_lookups
                    )
                    total_lookups = nested_res.lookup_count
                    if total_lookups > 10:
                        break

            if redirect_domain and redirect_domain.lower() not in visited:
                visited.add(redirect_domain.lower())
                nested_txt, success, _ = resolver.query_txt_with_status(redirect_domain)
                if success and nested_txt:
                    nested_res = cls.parse_spf_record(
                        nested_txt,
                        provenance=provenance,
                        historical_applicability=historical_applicability,
                        resolver=resolver,
                        recursive=True,
                        seen_domains=visited,
                        current_lookups=total_lookups
                    )
                    total_lookups = nested_res.lookup_count

            lookup_limit_exceeded = (total_lookups > 10)
            lookup_limit_risk = "LOOKUP_LIMIT_EXCEEDED" if lookup_limit_exceeded else None
            if lookup_limit_exceeded:
                limitations.append(f"SPF recursive lookup count ({total_lookups}) verified exceeding RFC 7208 limit of 10.")
        else:
            # Top-level mechanism count only
            total_lookups = top_level_lookups
            if provenance == AuthProvenanceSource.PASSIVE_CAPTURE:
                lookup_count_status = "NOT_EVALUATED"
                lookup_limit_exceeded = None
                lookup_limit_risk = None
            else:
                lookup_count_status = "ESTIMATED"
                if top_level_lookups > 10:
                    lookup_limit_risk = "POTENTIAL_LOOKUP_LIMIT_RISK"
                    lookup_limit_exceeded = False  # Not claimed as exact RFC 7208 violation without recursive evaluation
                    limitations.append(
                        f"SPF top-level mechanism count ({top_level_lookups}) suggests potential lookup limit risk; exact count is ESTIMATED."
                    )
                else:
                    lookup_limit_risk = None
                    lookup_limit_exceeded = False

        status = DNSAuthStatus.VALID
        if provenance == AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT:
            status = DNSAuthStatus.ACTIVE_ENRICHMENT
        elif provenance == AuthProvenanceSource.PASSIVE_CAPTURE:
            status = DNSAuthStatus.OBSERVED_PASSIVE

        return SPFRecordDetails(
            status=status,
            raw_record=raw_spf,
            version=version,
            policy_qualifier=qualifier,
            mechanisms=mechanisms,
            include_domains=include_domains,
            redirect_domain=redirect_domain,
            lookup_count=total_lookups,
            lookup_count_status=lookup_count_status,
            lookup_limit_exceeded=lookup_limit_exceeded,
            lookup_limit_risk=lookup_limit_risk,
            syntax_valid=True,
            spf_policy_present=True,
            spf_message_result=None,
            analysis_limitations=limitations
        )

    # -----------------------------------------------------------------------
    # 2. DKIM Header & DNS Key Parsing
    # -----------------------------------------------------------------------
    @classmethod
    def parse_dkim_header(
        cls,
        dkim_header_value: str,
        provenance: AuthProvenanceSource = AuthProvenanceSource.EML_HEADER
    ) -> DKIMRecordDetails:
        """Parses DKIM-Signature header per RFC 6376 without fabricating cryptographic verification."""
        tags: Dict[str, str] = {}
        for part in dkim_header_value.split(";"):
            part_clean = part.strip()
            if "=" in part_clean:
                k, v = part_clean.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        domain = tags.get("d")
        selector = tags.get("s")
        alg = tags.get("a")
        canon = tags.get("c")
        body_hash = tags.get("bh")

        return DKIMRecordDetails(
            status=DNSAuthStatus.OBSERVED_PASSIVE if provenance == AuthProvenanceSource.PASSIVE_CAPTURE else DNSAuthStatus.VALID,
            selector=selector,
            signing_domain=domain,
            algorithm=alg,
            canonicalization=canon,
            body_hash_present=bool(body_hash),
            body_hash=body_hash,
            dkim_verification_status="NOT_VERIFIED",
            signature_present=True,
            analysis_limitations=[
                "DKIM signature header observed; cryptographic signature and body hash integrity verification was NOT performed."
            ]
        )

    @classmethod
    def parse_dkim_dns_key(
        cls,
        txt_records: List[str],
        selector: str,
        domain: str
    ) -> DKIMRecordDetails:
        """Parses DKIM DNS public key record (_domainkey) per RFC 6376."""
        dkim_records = [t.strip() for t in txt_records if "v=DKIM1" in t or "p=" in t]
        if not dkim_records:
            return DKIMRecordDetails(
                status=DNSAuthStatus.UNAVAILABLE,
                selector=selector,
                signing_domain=domain,
                dkim_verification_status="NOT_VERIFIED",
                signature_present=False,
                analysis_limitations=[f"No DKIM public key published at {selector}._domainkey.{domain}."]
            )

        raw_key = dkim_records[0]
        tags: Dict[str, str] = {}
        for part in raw_key.split(";"):
            part_clean = part.strip()
            if "=" in part_clean:
                k, v = part_clean.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        k_type = tags.get("k", "rsa").upper()
        p_val = tags.get("p", "")

        return DKIMRecordDetails(
            status=DNSAuthStatus.ACTIVE_ENRICHMENT,
            selector=selector,
            signing_domain=domain,
            public_key_record=raw_key,
            public_key_type=k_type,
            public_key_bits=len(p_val) * 6 if p_val else None,
            dkim_verification_status="NOT_VERIFIED",
            signature_present=False,
            analysis_limitations=[
                "DKIM DNS public key observed; message signature verification was NOT performed (dkim_verification_status is NOT_VERIFIED)."
            ]
        )

    # -----------------------------------------------------------------------
    # 3. DMARC Parsing & Assessment
    # -----------------------------------------------------------------------
    @classmethod
    def parse_dmarc_record(
        cls,
        dmarc_txt: Optional[str],
        provenance: AuthProvenanceSource = AuthProvenanceSource.PASSIVE_CAPTURE,
        historical_applicability: HistoricalApplicability = HistoricalApplicability.UNKNOWN
    ) -> DMARCRecordDetails:
        """Parses DMARC policy record per RFC 7489."""
        if not dmarc_txt or not dmarc_txt.strip().startswith("v=DMARC1"):
            status = (
                DNSAuthStatus.NOT_OBSERVED
                if provenance == AuthProvenanceSource.PASSIVE_CAPTURE
                else DNSAuthStatus.UNAVAILABLE
            )
            return DMARCRecordDetails(
                status=status,
                message_dmarc_result="NOT_EVALUATED",
                analysis_limitations=["No DMARC (v=DMARC1) TXT record was observed at _dmarc.<domain>."]
            )

        clean_dmarc = dmarc_txt.strip()
        tags: Dict[str, str] = {}
        for part in clean_dmarc.split(";"):
            part_clean = part.strip()
            if "=" in part_clean:
                k, v = part_clean.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        p_val = tags.get("p", "none").lower()
        sp_val = tags.get("sp", p_val).lower()
        pct_val = 100
        if "pct" in tags:
            try:
                pct_val = int(tags["pct"])
            except ValueError:
                pct_val = 100

        rua_list = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
        ruf_list = [u.strip() for u in tags.get("ruf", "").split(",") if u.strip()]
        adkim = tags.get("adkim", "r").lower()
        aspf = tags.get("aspf", "r").lower()

        status = DNSAuthStatus.VALID
        if provenance == AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT:
            status = DNSAuthStatus.ACTIVE_ENRICHMENT
        elif provenance == AuthProvenanceSource.PASSIVE_CAPTURE:
            status = DNSAuthStatus.OBSERVED_PASSIVE

        return DMARCRecordDetails(
            status=status,
            raw_record=clean_dmarc,
            policy_p=p_val,
            subdomain_policy_sp=sp_val,
            percentage_pct=pct_val,
            rua_uris=rua_list,
            ruf_uris=ruf_list,
            adkim_mode=adkim,
            aspf_mode=aspf,
            syntax_valid=True,
            alignment_evaluated=False,
            message_dmarc_result="NOT_EVALUATED",
            analysis_limitations=[
                "DMARC policy record parsed; message-level DMARC validation is NOT_EVALUATED without verified SPF/DKIM envelope alignment."
            ]
        )

    # -----------------------------------------------------------------------
    # 4. MTA-STS Parsing & Assessment
    # -----------------------------------------------------------------------
    @classmethod
    def parse_mta_sts_record(
        cls,
        mta_sts_txt: Optional[str],
        provenance: AuthProvenanceSource = AuthProvenanceSource.PASSIVE_CAPTURE,
        https_policy: Optional[Dict[str, Any]] = None
    ) -> MTASTSRecordDetails:
        """Parses MTA-STS TXT record per RFC 8461."""
        if not mta_sts_txt or not mta_sts_txt.strip().startswith("v=STSv1"):
            status = (
                DNSAuthStatus.NOT_OBSERVED
                if provenance == AuthProvenanceSource.PASSIVE_CAPTURE
                else DNSAuthStatus.UNAVAILABLE
            )
            return MTASTSRecordDetails(
                status=status,
                analysis_limitations=["No MTA-STS (v=STSv1) TXT record was observed at _mta-sts.<domain>."]
            )

        clean_txt = mta_sts_txt.strip()
        tags: Dict[str, str] = {}
        for part in clean_txt.split(";"):
            part_clean = part.strip()
            if "=" in part_clean:
                k, v = part_clean.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        id_val = tags.get("id")
        mode_val = None
        max_age = None
        mx_list: List[str] = []
        https_fetched = False
        https_url = None
        fetch_ts = None

        if https_policy:
            https_fetched = True
            https_url = https_policy.get("url")
            fetch_ts = https_policy.get("fetched_at_utc")
            mode_val = https_policy.get("mode")
            max_age = https_policy.get("max_age")
            mx_list = https_policy.get("mx", [])

        status = DNSAuthStatus.VALID
        if provenance == AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT:
            status = DNSAuthStatus.ACTIVE_ENRICHMENT
        elif provenance == AuthProvenanceSource.PASSIVE_CAPTURE:
            status = DNSAuthStatus.OBSERVED_PASSIVE

        return MTASTSRecordDetails(
            status=status,
            raw_record=clean_txt,
            version="STSv1",
            id_tag=id_val,
            policy_mode=mode_val,
            max_age_seconds=max_age,
            mx_patterns=mx_list,
            https_policy_fetched=https_fetched,
            https_policy_url=https_url,
            https_fetch_timestamp=fetch_ts,
            analysis_limitations=[]
        )

    # -----------------------------------------------------------------------
    # 5. BIMI Parsing & Assessment
    # -----------------------------------------------------------------------
    @classmethod
    def parse_bimi_record(
        cls,
        bimi_txt: Optional[str],
        provenance: AuthProvenanceSource = AuthProvenanceSource.PASSIVE_CAPTURE
    ) -> BIMIRecordDetails:
        """Parses BIMI TXT record."""
        if not bimi_txt or not bimi_txt.strip().startswith("v=BIMI1"):
            status = (
                DNSAuthStatus.NOT_OBSERVED
                if provenance == AuthProvenanceSource.PASSIVE_CAPTURE
                else DNSAuthStatus.UNAVAILABLE
            )
            return BIMIRecordDetails(
                status=status,
                vmc_validation_status="NOT_VALIDATED",
                brand_validation_claimed=False,
                analysis_limitations=["No BIMI (v=BIMI1) TXT record was observed."]
            )

        clean_bimi = bimi_txt.strip()
        tags: Dict[str, str] = {}
        for part in clean_bimi.split(";"):
            part_clean = part.strip()
            if "=" in part_clean:
                k, v = part_clean.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        loc = tags.get("l")
        auth = tags.get("a")

        status = DNSAuthStatus.VALID
        if provenance == AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT:
            status = DNSAuthStatus.ACTIVE_ENRICHMENT
        elif provenance == AuthProvenanceSource.PASSIVE_CAPTURE:
            status = DNSAuthStatus.OBSERVED_PASSIVE

        return BIMIRecordDetails(
            status=status,
            raw_record=clean_bimi,
            version="BIMI1",
            location_svg=loc,
            authority_vmc=auth,
            vmc_validation_status="NOT_VALIDATED",
            brand_validation_claimed=False,
            analysis_limitations=[
                "BIMI record format observed; VMC certificate trust and brand logo validation were NOT performed (vmc_validation_status is NOT_VALIDATED)."
            ]
        )

    # -----------------------------------------------------------------------
    # 6. DANE TLSA & DNSSEC Parsing
    # -----------------------------------------------------------------------
    @classmethod
    def parse_dane_record(
        cls,
        tlsa_records: List[str],
        provenance: AuthProvenanceSource = AuthProvenanceSource.PASSIVE_CAPTURE
    ) -> DANERecordDetails:
        """Parses DANE TLSA records per RFC 6698."""
        if not tlsa_records:
            status = (
                DNSAuthStatus.NOT_OBSERVED
                if provenance == AuthProvenanceSource.PASSIVE_CAPTURE
                else DNSAuthStatus.UNAVAILABLE
            )
            return DANERecordDetails(
                status=status,
                tlsa_records=[],
                parsed_usages=[],
                dnssec_status="NOT_VALIDATED",
                analysis_limitations=["No DANE TLSA records observed for endpoint."]
            )

        usages: List[int] = []
        for rec in tlsa_records:
            parts = rec.strip().split()
            if parts:
                try:
                    usages.append(int(parts[0]))
                except ValueError:
                    pass

        status = DNSAuthStatus.VALID
        if provenance == AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT:
            status = DNSAuthStatus.ACTIVE_ENRICHMENT
        elif provenance == AuthProvenanceSource.PASSIVE_CAPTURE:
            status = DNSAuthStatus.OBSERVED_PASSIVE

        return DANERecordDetails(
            status=status,
            tlsa_records=tlsa_records,
            parsed_usages=usages,
            dnssec_status="NOT_VALIDATED",
            analysis_limitations=[
                "DANE TLSA records observed; cryptographic DNSSEC validation was NOT performed (dnssec_status is NOT_VALIDATED)."
            ]
        )

    # -----------------------------------------------------------------------
    # 7. Passive Session Evaluation
    # -----------------------------------------------------------------------
    @classmethod
    def evaluate_passive_session(
        cls,
        session: EmailSession
    ) -> DomainAuthenticationAssessment:
        """
        Extracts domain authentication state from purely passive session evidence.
        If DNS was not captured in the PCAP stream, returns NOT_OBSERVED without synthetic findings.
        """
        domain = session.server_hostname or "unknown.domain"

        spf = SPFRecordDetails(
            status=DNSAuthStatus.NOT_OBSERVED,
            lookup_count_status="NOT_EVALUATED",
            lookup_limit_exceeded=None,
            lookup_limit_risk=None,
            analysis_limitations=["No DNS SPF queries or responses observed in passive capture."]
        )
        dmarc = DMARCRecordDetails(
            status=DNSAuthStatus.NOT_OBSERVED,
            message_dmarc_result="NOT_EVALUATED",
            analysis_limitations=["No DNS DMARC queries or responses observed in passive capture."]
        )
        mta_sts = MTASTSRecordDetails(
            status=DNSAuthStatus.NOT_OBSERVED,
            analysis_limitations=["No DNS MTA-STS queries or responses observed in passive capture."]
        )
        bimi = BIMIRecordDetails(
            status=DNSAuthStatus.NOT_OBSERVED,
            vmc_validation_status="NOT_VALIDATED",
            brand_validation_claimed=False,
            analysis_limitations=["No DNS BIMI queries or responses observed in passive capture."]
        )
        dane = DANERecordDetails(
            status=DNSAuthStatus.NOT_OBSERVED,
            dnssec_status="NOT_VALIDATED",
            analysis_limitations=["No DANE TLSA queries or responses observed in passive capture."]
        )

        return DomainAuthenticationAssessment(
            domain=domain,
            source=AuthProvenanceSource.PASSIVE_CAPTURE,
            historical_applicability=HistoricalApplicability.CAPTURE_TIME_EVIDENCE,
            queried_at_utc=None,
            resolver_provider=None,
            resolver_endpoint=None,
            is_active_enrichment=False,
            spf=spf,
            dkim=None,
            dmarc=dmarc,
            mta_sts=mta_sts,
            bimi=bimi,
            dane=dane,
            overall_auth_posture="NOT_OBSERVED_PASSIVE",
            authoritative_boundary_disclaimer=(
                "Passive capture mode: DNS and email authentication records were not present in the capture stream."
            ),
            limitations=["Passive PCAP analysis did not contain DNS query/response frames for domain authentication."]
        )

    # -----------------------------------------------------------------------
    # 8. Active Domain Enrichment
    # -----------------------------------------------------------------------
    @classmethod
    def evaluate_active_domain(
        cls,
        domain: str,
        fetch_mta_sts_https: bool = False,
        resolver: Optional[DNSResolver] = None,
        evaluate_spf_recursive: bool = True
    ) -> DomainAuthenticationAssessment:
        """
        Executes opt-in active DNS queries for SPF, DMARC, MTA-STS, BIMI, and DANE.
        Result is strictly labeled as CURRENT_STATE_ONLY active enrichment.
        """
        clean_domain = domain.strip().lower().rstrip(".")
        res = resolver or DNSResolver(timeout_sec=3.0)
        query_time = datetime.now(timezone.utc).isoformat()

        # Query records with explicit error/timeout capture
        txt_records, spf_ok, spf_err = res.query_txt_with_status(clean_domain)
        dmarc_records, dmarc_ok, dmarc_err = res.query_txt_with_status(f"_dmarc.{clean_domain}")
        mta_sts_records, mta_ok, mta_err = res.query_txt_with_status(f"_mta-sts.{clean_domain}")
        bimi_records, bimi_ok, bimi_err = res.query_txt_with_status(f"default._bimi.{clean_domain}")
        tlsa_records, tlsa_ok, tlsa_err = res.query_tlsa_with_status(f"_25._tcp.mail.{clean_domain}")

        https_policy = None
        if fetch_mta_sts_https:
            https_policy = res.fetch_mta_sts_policy(clean_domain)

        # Parse SPF (with recursive accounting if enabled and query succeeded)
        if spf_ok:
            spf = cls.parse_spf_record(
                txt_records,
                provenance=AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT,
                historical_applicability=HistoricalApplicability.CURRENT_STATE_ONLY,
                resolver=res if evaluate_spf_recursive else None,
                recursive=evaluate_spf_recursive
            )
        else:
            spf = SPFRecordDetails(
                status=DNSAuthStatus.UNAVAILABLE,
                lookup_count_status="NOT_EVALUATED",
                lookup_limit_exceeded=None,
                lookup_limit_risk=None,
                spf_policy_present=False,
                analysis_limitations=[f"DNS SPF query failed or timed out: {spf_err or 'Resolver unavailable'}."]
            )

        # Parse DMARC
        if dmarc_ok:
            dmarc_txt = dmarc_records[0] if dmarc_records else None
            dmarc = cls.parse_dmarc_record(
                dmarc_txt,
                provenance=AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT,
                historical_applicability=HistoricalApplicability.CURRENT_STATE_ONLY
            )
        else:
            dmarc = DMARCRecordDetails(
                status=DNSAuthStatus.UNAVAILABLE,
                message_dmarc_result="NOT_EVALUATED",
                analysis_limitations=[f"DNS DMARC query failed or timed out: {dmarc_err or 'Resolver unavailable'}."]
            )

        # Parse MTA-STS
        if mta_ok:
            mta_sts_txt = mta_sts_records[0] if mta_sts_records else None
            mta_sts = cls.parse_mta_sts_record(
                mta_sts_txt,
                provenance=AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT,
                https_policy=https_policy
            )
        else:
            mta_sts = MTASTSRecordDetails(
                status=DNSAuthStatus.UNAVAILABLE,
                analysis_limitations=[f"DNS MTA-STS query failed or timed out: {mta_err or 'Resolver unavailable'}."]
            )

        # Parse BIMI
        if bimi_ok:
            bimi_txt = bimi_records[0] if bimi_records else None
            bimi = cls.parse_bimi_record(
                bimi_txt,
                provenance=AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT
            )
        else:
            bimi = BIMIRecordDetails(
                status=DNSAuthStatus.UNAVAILABLE,
                vmc_validation_status="NOT_VALIDATED",
                brand_validation_claimed=False,
                analysis_limitations=[f"DNS BIMI query failed or timed out: {bimi_err or 'Resolver unavailable'}."]
            )

        # Parse DANE
        if tlsa_ok:
            dane = cls.parse_dane_record(
                tlsa_records,
                provenance=AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT
            )
        else:
            dane = DANERecordDetails(
                status=DNSAuthStatus.UNAVAILABLE,
                dnssec_status="NOT_VALIDATED",
                analysis_limitations=[f"DNS DANE query failed or timed out: {tlsa_err or 'Resolver unavailable'}."]
            )

        # Compute overall active posture
        if dmarc.policy_p == "reject" and spf.policy_qualifier == "-all":
            overall = "ROBUST"
        elif dmarc.policy_p in ["reject", "quarantine"]:
            overall = "MODERATE"
        elif dmarc.policy_p == "none" or spf.spf_policy_present:
            overall = "BASIC"
        else:
            overall = "DEFICIENT"

        return DomainAuthenticationAssessment(
            domain=clean_domain,
            source=AuthProvenanceSource.ACTIVE_DNS_ENRICHMENT,
            historical_applicability=HistoricalApplicability.CURRENT_STATE_ONLY,
            queried_at_utc=query_time,
            resolver_provider=res.provider_name,
            resolver_endpoint=res.endpoint_url,
            is_active_enrichment=True,
            spf=spf,
            dkim=None,
            dmarc=dmarc,
            mta_sts=mta_sts,
            bimi=bimi,
            dane=dane,
            overall_auth_posture=overall,
            authoritative_boundary_disclaimer=(
                "Active DNS enrichment reflects live DNS state at queried_at_utc and does NOT alter or represent historical capture evidence."
            ),
            limitations=[
                "Active live DNS lookup reflects current state and must not be used to assert historical DNS policy during past capture sessions."
            ]
        )

    # -----------------------------------------------------------------------
    # 9. Offline / Manual Provided Records Evaluation
    # -----------------------------------------------------------------------
    @classmethod
    def evaluate_provided_records(
        cls,
        domain: str,
        txt_records: Optional[List[str]] = None,
        dmarc_txt: Optional[str] = None,
        mta_sts_txt: Optional[str] = None,
        bimi_txt: Optional[str] = None,
        tlsa_records: Optional[List[str]] = None
    ) -> DomainAuthenticationAssessment:
        """Evaluates explicitly supplied offline DNS records without performing network calls."""
        clean_domain = domain.strip().lower().rstrip(".")
        query_time = datetime.now(timezone.utc).isoformat()

        spf = cls.parse_spf_record(
            txt_records or [],
            provenance=AuthProvenanceSource.OFFLINE_MANUAL_INPUT,
            historical_applicability=HistoricalApplicability.UNKNOWN
        )
        dmarc = cls.parse_dmarc_record(
            dmarc_txt,
            provenance=AuthProvenanceSource.OFFLINE_MANUAL_INPUT,
            historical_applicability=HistoricalApplicability.UNKNOWN
        )
        mta_sts = cls.parse_mta_sts_record(
            mta_sts_txt,
            provenance=AuthProvenanceSource.OFFLINE_MANUAL_INPUT
        )
        bimi = cls.parse_bimi_record(
            bimi_txt,
            provenance=AuthProvenanceSource.OFFLINE_MANUAL_INPUT
        )
        dane = cls.parse_dane_record(
            tlsa_records or [],
            provenance=AuthProvenanceSource.OFFLINE_MANUAL_INPUT
        )

        if dmarc.policy_p == "reject" and spf.policy_qualifier == "-all":
            overall = "ROBUST"
        elif dmarc.policy_p in ["reject", "quarantine"]:
            overall = "MODERATE"
        elif dmarc.policy_p == "none" or spf.spf_policy_present:
            overall = "BASIC"
        else:
            overall = "DEFICIENT"

        return DomainAuthenticationAssessment(
            domain=clean_domain,
            source=AuthProvenanceSource.OFFLINE_MANUAL_INPUT,
            historical_applicability=HistoricalApplicability.UNKNOWN,
            queried_at_utc=query_time,
            resolver_provider=None,
            resolver_endpoint=None,
            is_active_enrichment=False,
            spf=spf,
            dkim=None,
            dmarc=dmarc,
            mta_sts=mta_sts,
            bimi=bimi,
            dane=dane,
            overall_auth_posture=overall,
            authoritative_boundary_disclaimer=(
                "Evaluated from offline supplied records without active DNS lookup."
            ),
            limitations=["Records were provided manually / offline; DNS provenance unverified."]
        )
