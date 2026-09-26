# SecureMailScope X

> **Explainable AI-Driven Email Cryptographic Forensics with Post-Quantum Readiness and Blockchain-Backed Chain of Custody**  
> *Problem Statement:* SIH26159 | Smart India Hackathon 2026

---

## 1. Project Overview

SecureMailScope X is an enterprise-grade, offline-first forensic investigation and mail security posture management platform designed for Windows 11 x64 and air-gapped forensic laboratories.

The system passively analyzes `.pcap` and `.pcapng` network captures containing email protocols (**SMTP**, **IMAP**, **POP3**), active-scans live mail endpoints, audits TLS configurations, computes explainable AI security scores, tracks cryptographic posture drift, automates deterministic forensic alerting, generates verifiable remediation playbooks, and plans hybrid post-quantum cryptography (PQC) transitions.

### Core Forensic Philosophy
$$\text{Raw PCAP} \longrightarrow \text{Forensic Evidence} \longrightarrow \text{Security Analysis} \longrightarrow \text{Explainable AI} \longrightarrow \text{PQC Roadmap} \longrightarrow \text{Verify-After-Fix} \longrightarrow \text{Blockchain Custody}$$

- **Zero Fake Data**: Every finding is backed by frame numbers, timestamps, packet payloads, or verified scan evidence.
- **TLS 1.3 Honesty**: Encrypted handshakes and certificate visibility boundaries are accurately reported rather than simulated.
- **Offline & Local Execution**: Completely self-contained with SQLite, pure-Python cryptography (Ed25519/RSA-PSS), local SHA-256 Merkle trees, and local TShark integration. Zero cloud dependencies.

---

## 2. Comprehensive Platform Capabilities (Phases 1–25)

1. **Protocol Dissectors & State Trackers**: Passive SMTP, IMAP, and POP3 state machines tracking STARTTLS negotiations and cleartext downgrades.
2. **Cryptographic Engine & PQC Catalog**: IANA cipher mapping, PFS classification, TLS version extraction, and NIST PQC algorithm flags.
3. **Deterministic Scoring & Explainable AI (CSPI)**: Sub-score breakdowns for Protocol Security, Cryptographic Strength, Certificate Hygiene, and Forward Secrecy.
4. **Digital Evidence Locker & Merkle Chain of Custody**: Cryptographic integrity manifests, immutable versioning, and Ed25519/RSA-PSS sign-off.
5. **Multi-Analyst RBAC & Cryptographic Peer Sign-Off**: 5-role capability matrix, multi-analyst case assignment, and M-of-N quorum reviews.
6. **Continuous Posture Monitoring & Drift Engine**: Local scheduler, baseline pinning, and regression drift detection.
7. **Automated Forensic Alerting Engine**: Deterministic rule evaluation against findings and drift events, cooldown deduplication, and local syslog/webhook delivery.
8. **Evidence-Based Remediation & Simulate-Fix Engine**: Advisory configuration playbooks (Postfix, Exim, Dovecot, Sendmail) and verify-after-fix validation.
9. **Post-Quantum Cryptography Migration Planner**: Categorical HNDL quantum exposure modeling, 7-phase transition roadmaps, and gap analysis.
10. **SIEM / SOC Integration**: CEF, RFC 5424 Syslog, and JSON event export with transport delivery audit trails.

---

## 3. Quick Start & Execution

### Prerequisites
- Python 3.10+ (Tested on Python 3.14 on Windows 11 x64)
- Node.js 18+ and npm
- Wireshark / TShark installed (Default path: `C:\Program Files\Wireshark\tshark.exe`)

### Backend Setup & Execution
```powershell
# In project root:
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation will be available at `http://127.0.0.1:8000/docs`.

### Frontend Setup & Execution
```powershell
# In project root:
cd frontend
npm install
npm run dev
```
Web dashboard will be available at `http://localhost:5173`.

### Running Full Test Suite (541 Tests)
```powershell
python -m unittest discover -s backend/tests -p "test_*.py"
```

### Production Build
```powershell
cd frontend
npm run build
```

---

## 4. Documentation Links
- [Architecture & Schema Design](file:///d:/SecureMailScope%20X/ARCHITECTURE.md)
- [Project Status & Phase History](file:///d:/SecureMailScope%20X/PROJECT_STATUS.md)
- [Windows 11 Installation Guide](file:///d:/SecureMailScope%20X/INSTALL_WINDOWS.md)
- [Demonstration & Evaluator Guide](file:///d:/SecureMailScope%20X/DEMO_GUIDE.md)
- [Security Policy & Threat Model](file:///d:/SecureMailScope%20X/SECURITY.md)
- [Final Release Checklist](file:///d:/SecureMailScope%20X/FINAL_RELEASE_CHECKLIST.md)

