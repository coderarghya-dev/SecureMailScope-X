# SecureMailScope X — Architecture Specification

## 1. Passive PCAP Forensics Pipeline (Phases 1 & 2)

```
                  ┌──────────────────────────────────────────────┐
                  │    Raw Network Capture (.pcap / .pcapng)    │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │    TShark Dissection & Structured Extraction │
                  │  (TCP streams, email ports, TLS handshakes) │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │         TCP Stream Session Grouping          │
                  │   (Reconstructs Bi-directional TCP flows)    │
                  └──────────────────────┬───────────────────────┘
                                         │
                ┌────────────────────────┴────────────────────────┐
                ▼                                                 ▼
┌───────────────────────────────┐                 ┌───────────────────────────────┐
│     SMTP Protocol Analyzer    │                 │     IMAP Protocol Analyzer    │
│  - 220 Server Greeting Banner │                 │  - Port 993 Direct TLS check  │
│  - Client EHLO / HELO         │                 │  - Port 143 CAPABILITY check  │
│  - 250 STARTTLS Advertisement │                 │  - STARTTLS command / OK resp │
│  - Client STARTTLS Request    │                 └───────────────┬───────────────┘
│  - 220 Ready to Start TLS     │                                 │
└───────────────┬───────────────┘                                 │
                │                                                 │
                └────────────────────────┬────────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │       TLS Cryptographic Handshake Dissector   │
                  │  - ClientHello: SNI, offered ciphers, ALPN   │
                  │  - ServerHello: Supported Versions (0x002b)  │
                  │  - True Version Detection: TLS 1.3 vs 1.2    │
                  │  - IANA Cipher Suite Resolution              │
                  │  - Forward Secrecy (PFS) Verification        │
                  │  - Passive Certificate Visibility Audit      │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │          Forensic Session Data Model         │
                  │   (EmailSession with full PacketEvidence)    │
                  └──────────────────────────────────────────────┘
```

## 2. Cryptographic Truth Rules

1. **RFC 8446 Version Verification**:
   - In TLS 1.3, the record layer version is fixed at `0x0303` (TLS 1.2) for legacy middlebox tolerance.
   - The authoritative negotiated version MUST be read from the `supported_versions` extension (`0x0304` = TLS 1.3).
   - Our dissector accurately correlates the extension to confirm TLS 1.3.

2. **Perfect Forward Secrecy (PFS)**:
   - Evaluated based on key exchange mechanism (`ECDHE` and `DHE`).
   - Static RSA key exchanges (`TLS_RSA_WITH_*`) are classified as having NO Forward Secrecy.
   - All TLS 1.3 cipher suites inherently guarantee Forward Secrecy by standard specification.

3. **Certificate Visibility Forensics**:
   - TLS 1.3 encrypts all certificates in the Encrypted Extensions stream.
   - Passive monitors cannot extract plaintext certificates without decryption secrets.
   - Factual report: `Unavailable from passive capture (TLS 1.3 encrypted handshake)`.

## 3. Multi-Analyst RBAC & Cryptographic Peer Sign-Off Architecture (Phase 20)

```
┌────────────────────────────────────────────────────────────────────────┐
│              Multi-Analyst Role-Based Access Control (RBAC)            │
│   FORENSIC_ANALYST  |  LEAD_INVESTIGATOR  |  REVIEWER  |  AUDITOR  |   │
│                                  ADMIN                                 │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Case Assignment Model                           │
│   - Primary Investigator                                               │
│   - Assigned Forensic Analysts                                         │
│   - Assigned Independent Reviewers                                     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               Deterministic Case Manifest & Mutation Tracking          │
│   - Canonical sorting of artifacts, analyses, notes, and metadata      │
│   - SHA-256 hash strictly computed per case state revision             │
│   - Any state mutation invalidates previous review approvals           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│           Cryptographic Peer Sign-Off & M-of-N Approval Engine         │
│   - Review decisions (APPROVED / CHANGES_REQUESTED / REJECTED)         │
│   - Asymmetric digital signatures (Ed25519 / RSA-PSS)                  │
│   - Canonical payload binding: {case_id, manifest_sha256, reviewer_id, │
│                                 decision, timestamp}                   │
│   - M-of-N Quorum Thresholds & Lead Investigator requirement           │
│   - Self-Review Prevention Enforcement                                 │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  Authorized Case Sealing & Chain Audit                 │
│   - AuthorizationService capability check: SEAL_CASE                   │
│   - Quorum satisfaction on CURRENT manifest verification               │
│   - Append-only hash-chained audit events: CASE_REVIEW_APPROVED,       │
│     CASE_SIGNOFF_VERIFIED, CASE_SEAL_AUTHORIZED, ROLE_CHANGED          │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 21. Continuous Mail Security Posture Monitoring & Drift Engine (Phase 21)

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Monitored Targets Ledger                        │
│   - Hostname, Port (25, 465, 587, 110, 143, 993, 995), Protocol       │
│   - Security Mode (PLAIN_WITH_STARTTLS, DIRECT_TLS)                    │
│   - Local Schedule (MANUAL, HOURLY, DAILY, WEEKLY)                     │
│   - Authoritative Pinned Baseline Reference                            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│              Opt-In Active Scanner & Canonical Snapshots               │
│   - DNS Pinning & SSRF defense; strictly bounded timeouts (<=5.0s)     │
│   - Observed: Reachable, STARTTLS, TLS version, Cipher, Certificate,   │
│     PFS status, PQC readiness                                          │
│   - Deterministic SHA-256 Canonical Snapshot Hashing                   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   Configuration Drift Detection Engine                 │
│   - Reachability transitions (ENDPOINT_BECAME_UNREACHABLE / RECOVERED) │
│   - TLS Downgrade / Upgrade detection                                  │
│   - STARTTLS disablement / enablement                                  │
│   - Certificate expiration / renewal / modification                    │
│   - PFS status loss / gain, PQC readiness transitions                  │
│   - Classification: REGRESSION, IMPROVEMENT, NEUTRAL, UNKNOWN          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 SIEM Telemetry & RBAC-Guarded Workflows                │
│   - Drift events derived into NormalizedSOCEvent (POSTURE_DRIFT)       │
│   - Local-only evaluation; zero unsolicited network deliveries         │
│   - RBAC Capabilities: VIEW_MONITORING, MANAGE_MONITORED_TARGETS,      │
│     RUN_MONITOR_SCAN, PIN_POSTURE_BASELINE, VIEW_DRIFT_HISTORY         │
└────────────────────────────────────────────────────────────────────────┘
```


