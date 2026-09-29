# 🛡️ SecureMailScope X

<div align="center">

```
   ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗███╗   ███╗ █████╗ ██╗██╗     ███████╗ ██████╗ ██████╗ ██████╗ ███████╗   ██╗  ██╗
   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝████╗ ████║██╔══██╗██║██║     ██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝   ╚██╗██╔╝
   ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ██╔████╔██║███████║██║██║     ███████╗██║     ██║   ██║██████╔╝█████╗      ╚███╔╝ 
   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██║╚██╔╝██║██╔══██║██║██║     ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝      ██╔██╗ 
   ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗██║ ╚═╝ ██║██║  ██║██║███████╗███████║╚██████╗╚██████╔╝██║     ███████╗██╗██╔╝ ██╗
   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝╚═╝  ╚═╝
```

### **Next-Gen Explainable AI Email Cryptographic Forensics, Post-Quantum Readiness & Blockchain-Sealed Chain of Custody**

[![SIH 2026 Problem Statement](https://img.shields.io/badge/SIH%202026-Problem%20Statement%20SIH26159-00B4D8?style=for-the-badge&logo=target)](https://www.sih.gov.in/)
[![Build & Test Status](https://img.shields.io/badge/Tests-541%2F541%20PASSED%20(100%25)-00F5D4?style=for-the-badge&logo=checkmarx)](https://github.com/)
[![Python Version](https://img.shields.io/badge/Backend-Python%203.10%20%7C%203.14-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Framework-FastAPI%200.115+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Frontend](https://img.shields.io/badge/Frontend-React%2018%20%7C%20Vite%20%7C%20TS-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![Wireshark/TShark](https://img.shields.io/badge/Dissection-TShark%204.6+-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)](https://www.wireshark.org/)
[![NIST Post-Quantum](https://img.shields.io/badge/PQC-NIST%20FIPS%20203%20%7C%20204%20%7C%20205-7209B7?style=for-the-badge&logo=quantum)](https://csrc.nist.gov/)
[![License](https://img.shields.io/badge/License-MIT-F72585?style=for-the-badge)](LICENSE)

[Key Features](#-key-features) • [Architecture](#-architecture--pipeline) • [Forensic Capabilities](#-forensic-capabilities) • [PQC & Quantum Threat](#-post-quantum-cryptography-pqc--hndl) • [Blockchain Custody](#-blockchain-backed-chain-of-custody) • [Installation](#-installation--quickstart) • [REST API](#-rest-api-reference) • [Demo Guide](#-competition-demo-workflow)

</div>

---

## 📌 Executive Summary

**SecureMailScope X** is an enterprise-grade, offline-first forensic investigation platform designed for cyber defense teams, forensic investigators, CERTs, and security auditors. It solves **Problem Statement SIH26159** by delivering automated, multi-protocol passive email stream extraction, deep TLS 1.3 cryptographic dissection, explainable AI (XAI) risk scoring, deterministic remediation playbooks, continuous posture drift tracking, and tamper-evident Merkle-tree blockchain evidence sealing.

```
       ╔══════════════════════════════════════════════════════════════════════════════════╗
       ║                             CORE FORENSIC PHILOSOPHY                             ║
       ║  Raw PCAP ➔ Passive Dissection ➔ Zero-Trust Crypto Audit ➔ Explainable AI ➔      ║
       ║  PQC HNDL Modeling ➔ Advisory Remediation ➔ Merkle Evidence Sealing ➔ SOC Export ║
       ╚══════════════════════════════════════════════════════════════════════════════════╝
```

### 🌟 Why SecureMailScope X?

| Traditional Mail Security | SecureMailScope X |
| :--- | :--- |
| ❌ Active-only SMTP scanning (misses real in-flight attacks) | ✅ **Dual-Mode**: Full Passive PCAP/PCAPNG Dissection + Opt-In Active Scanning |
| ❌ Black-box heuristic scoring | ✅ **Explainable AI (CSPI)** with deterministic mathematical sub-score trees |
| ❌ Assumes TLS 1.3 implies Perfect Forward Secrecy | ✅ **Evidence-Bounded Truth**: Validates explicit key-exchange parameters (`ECDHE`/`DHE`) |
| ❌ Fabricates certificate findings on encrypted handshakes | ✅ **TLS 1.3 Spec Compliance**: Accurately bounds unobservable encrypted extensions |
| ❌ Static advisory documentation | ✅ **Simulate-Fix Engine** with verify-after-fix validation against live PCAPs |
| ❌ Vulnerable plain-text forensic case notes | ✅ **Cryptographic Chain of Custody**: SHA-256 Merkle trees & Ed25519/RSA-PSS M-of-N sign-offs |
| ❌ Ignores upcoming quantum decryption threats | ✅ **NIST FIPS 203/204/205 PQC Migration Planner** & Harvest Now Decrypt Later (HNDL) risk audit |

---

## ⚡ Key Features

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   FEATURE MATRIX OVERVIEW                                        │
├──────────────────────────────┬───────────────────────────────┬───────────────────────────────────┤
│ 📨 Passive Protocol Dissection│ 🔐 Cryptographic Deep Audit   │ 🤖 Explainable AI & ML Triage     │
│  • SMTP (Port 25, 465, 587)  │  • TLS 1.3 / 1.2 / 1.1 / 1.0  │  • Cryptographic Posture Index   │
│  • IMAP (Port 143, 993)      │  • 300+ IANA Cipher Suites    │  • Sub-Score Breakdown Matrix     │
│  • POP3 / STLS (Port 110, 995│  • Perfect Forward Secrecy    │  • Evidence-Bounded Confidence    │
├──────────────────────────────┼───────────────────────────────┼───────────────────────────────────┤
│ ⚛️ Post-Quantum Readiness     │ 🔗 Tamper-Proof Chain Custody │ 🔄 Posture Drift & Alerting       │
│  • HNDL Quantum Exposure     │  • SHA-256 Merkle Trees       │  • Continuous Baseline Pinning    │
│  • Hybrid PQC (ML-KEM-768)   │  • Asymmetric Ed25519 Signoff │  • Regression & Upgrade Detection │
│  • 7-Phase Transition Roadmaps│ • Multi-Analyst M-of-N Quorum│  • Syslog, CEF & Webhook Alerts   │
├──────────────────────────────┼───────────────────────────────┼───────────────────────────────────┤
│ 🛠️ Remediation Playbooks      │ 🔍 Deep Packet Explorer       │ 📄 Forensic Audit Reports         │
│  • Postfix, Exim, Dovecot    │  • Native Wireshark Frames    │  • Cryptographic PDF Generation   │
│  • In-Memory Risk Simulation │  • Hex & ASCII Stream View    │  • Executive & Judge Summaries    │
│  • Verify-After-Fix Engine   │  • BPF Filter Engine          │  • Merkle Proof Verification Badge│
└──────────────────────────────┴───────────────────────────────┴───────────────────────────────────┘
```

---

## 🏗️ Architecture & Pipeline

SecureMailScope X is built upon a modular, decoupled architecture ensuring sub-millisecond parsing, zero cloud dependency, and total forensic integrity.

```mermaid
flowchart TB
    subgraph INGESTION ["1. Ingestion & Pre-Flight Layer"]
        A["Network Capture (.pcap / .pcapng)"] --> B["SHA-256 Ingestion Hashing"]
        B --> C["TShark Dissection Engine\n(Wireshark 4.6+)"]
    end

    subgraph PROTOCOL_PARSERS ["2. Passive Multi-Protocol Dissectors"]
        C --> D1["SMTP State Machine\n(EHLO ➔ 250 STARTTLS ➔ TLS)"]
        C --> D2["IMAP State Machine\n(CAPABILITY ➔ STARTTLS / 993)"]
        C --> D3["POP3 / STLS Machine\n(CAPA ➔ STLS ➔ 995)"]
    end

    subgraph TLS_ENGINE ["3. Cryptographic Deep Audit"]
        D1 & D2 & D3 --> E["TLS Handshake Reconstructor"]
        E --> F1["True Version Resolver\n(Supported Versions 0x002b)"]
        E --> F2["IANA Cipher Catalog\n(300+ Ciphers, Bit-Strength)"]
        E --> F3["Forward Secrecy (PFS)\n(ECDHE / DHE / KeyShare)"]
        E --> F4["Passive Visibility Boundary\n(RFC 8446 Encrypted Certs)"]
    end

    subgraph SCORING_AI ["4. Deterministic Scoring & Explainable AI"]
        F1 & F2 & F3 & F4 --> G["Deterministic Rule Engine\n(25+ Standard Rules)"]
        G --> H1["Cryptographic Security Posture (CSPI)"]
        G --> H2["Capture Health & Quality Scorer"]
        G --> H3["Evidence Confidence Scorer (95%+)"]
        G --> H4["ML Risk Triage Classifier"]
    end

    subgraph REMEDIATION_PQC ["5. PQC Roadmaps & Remediation Engine"]
        H1 & H4 --> I1["HNDL Quantum Exposure Calculator"]
        I1 --> I2["7-Phase NIST PQC Transition Roadmap"]
        H1 --> J1["Advisory Configuration Playbooks\n(Postfix, Exim, Dovecot)"]
        J1 --> J2["Simulate-Fix Engine & Verify-After-Fix"]
    end

    subgraph CUSTODY_OUTPUT ["6. Sealing, Storage & Export"]
        H1 & I2 & J2 --> K["Digital Evidence Locker & Merkle Tree"]
        K --> L1["Ed25519 / RSA-PSS Peer Sign-Off"]
        K --> L2["Executive PDF Forensic Reports"]
        K --> L3["SIEM / SOC Telemetry (CEF, Syslog, JSON)"]
    end

    style INGESTION fill:#1e293b,stroke:#00b4d8,stroke-width:2px,color:#fff
    style PROTOCOL_PARSERS fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#fff
    style TLS_ENGINE fill:#1e1b4b,stroke:#818cf8,stroke-width:2px,color:#fff
    style SCORING_AI fill:#1e293b,stroke:#34d399,stroke-width:2px,color:#fff
    style REMEDIATION_PQC fill:#311042,stroke:#f472b6,stroke-width:2px,color:#fff
    style CUSTODY_OUTPUT fill:#0f172a,stroke:#fbbf24,stroke-width:2px,color:#fff
```

---

## 🔬 Forensic Capabilities

### 1. STARTTLS Handshake & Upgrade State Trackers
The system implements state machines tracking bidirectional TCP flows:
- **SMTP STARTTLS (RFC 3207)**: Identifies server greeting banners (`220`), client `EHLO`/`HELO`, capability advertisements (`250-STARTTLS`), client `STARTTLS` request command, and server response (`220 2.0.0 Ready to start TLS`).
- **IMAP STARTTLS (RFC 3501 / 2595)**: Tracks `CAPABILITY`, `STARTTLS` command, and `OK Begin TLS` transition.
- **POP3 STLS (RFC 2595 / 1939)**: Dissects `CAPA`, `STLS`, and `+OK Begin TLS negotiation`.
- **Cleartext Downgrade Stripping**: Detects MITM attacks where STARTTLS capability is stripped or negotiation fails back to plaintext credentials.

```
       Client                                                        Server
         │                                                             │
         │ ──────────── 1. TCP Handshake (SYN ➔ SYN-ACK ➔ ACK) ───────►│
         │◄──────────── 2. 220 mail.example.com ESMTP Postfix ─────────┤ (Frame 2291)
         │ ──────────── 3. EHLO client.local ─────────────────────────►│
         │◄──────────── 4. 250-STARTTLS Advertised ────────────────────┤
         │ ──────────── 5. STARTTLS Command Requested ────────────────►│ (Frame 2292)
         │◄──────────── 6. 220 2.0.0 Ready to start TLS (Accepted) ───┤ (Frame 2294)
         │                                                             │
         │ ═══════════════ TLS 1.3 CRYPTOGRAPHIC HANDSHAKE ═════════════ │
         │ ──────────── 7. ClientHello (Offers, SNI, KeyShares) ──────►│ (Frame 2295)
         │◄──────────── 8. ServerHello (Selected Cipher: 0x1302) ──────┤ (Frame 2298)
         │                                                             │
         │ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ENCRYPTED SMTP APPLICATION DATA ▓▓▓▓▓▓▓▓▓▓▓▓▓│
         │ ◄═══════════ (Protected TLS 1.3 Records: Frames 2300+) ════►│
```

---

### 2. Cryptographic Deep Inspection & True TLS 1.3 Detection
- **RFC 8446 Version Compliance**: Resolves middlebox compatibility quirks (`legacy_record_version = 0x0303`) by extracting authoritative negotiated version from the `supported_versions` extension (`0x0304` = TLS 1.3).
- **300+ IANA Cipher Suite Mapping**: Evaluates key exchange, symmetric encryption algorithm (AES-GCM, ChaCha20-Poly1305, 3DES, RC4), authentication mechanism, and MAC integrity.
- **Perfect Forward Secrecy (PFS)**: Accurately checks for ephemeral key exchange (`ECDHE`, `DHE`, `X25519`). If passive evidence lacks explicit key-share frames, reports bounded truth: `Unknown / Insufficient passive evidence`.
- **Certificate Visibility Auditing**: Accurately honors the TLS 1.3 specification where server certificates are encrypted post-ServerHello.

---

### 3. Explainable AI (XAI) & Cryptographic Posture Index (CSPI)

Rather than generating black-box confidence scores, SecureMailScope X calculates the **Cryptographic Security Posture Index (CSPI)** using an explainable mathematical tree:

$$\text{CSPI} = \omega_p \cdot S_{\text{protocol}} + \omega_c \cdot S_{\text{crypto}} + \omega_h \cdot S_{\text{cert}} + \omega_f \cdot S_{\text{pfs}} - \sum \text{Deductions}_{\text{risk}}$$

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                     CSPI EXPLAINABLE SCORING BREAKDOWN MATRIX                          │
├──────────────────────────┬────────┬─────────────────────────┬──────────────────────────┤
│ Dimension                │ Weight │ Evaluation Metrics      │ Target Criteria          │
├──────────────────────────┼────────┼─────────────────────────┼──────────────────────────┤
│ 1. Protocol Security     │  30%   │ STARTTLS vs Direct TLS  │ Mandatory TLS, No Stripping
│ 2. Cryptographic Strength│  35%   │ Cipher, TLS Version     │ TLS 1.3 / AES-256-GCM    │
│ 3. Certificate Hygiene   │  15%   │ SAN, Expiry, Key Length │ Valid Root CA, 2048+ RSA │
│ 4. Forward Secrecy (PFS) │  20%   │ Ephemeral Key Exchange  │ ECDHE (X25519 / P-384)   │
└──────────────────────────┴────────┴─────────────────────────┴──────────────────────────┘
```

---

## ⚛️ Post-Quantum Cryptography (PQC) & HNDL

Adversaries are currently executing **Harvest Now, Decrypt Later (HNDL)** attacks—intercepting and storing encrypted enterprise email traffic today to decrypt once cryptanalytically relevant quantum computers (CRQCs) emerge (via Shor's Algorithm).

```
   ┌─────────────────────────────────────────────────────────────────────────────────────┐
   │                        HNDL QUANTUM THREAT TIMELINE                                 │
   │                                                                                     │
   │   TODAY (Harvesting)                 TRANSITION ERA                 QUANTUM DAY (Q-Day)
   │  ┌───────────────────────┐         ┌─────────────────────────┐     ┌──────────────┐ │
   │  │ Adversary intercepts  │ ──────► │ Hybrid PQC Deployment   │────►│ Shor's Algo  │ │
   │  │ & stores classical    │         │ (X25519 + ML-KEM-768)   │     │ breaks RSA / │ │
   │  │ RSA/ECDHE mail traces │         │ NIST FIPS 203 Standards │     │ ECC Ciphers  │ │
   │  └───────────────────────┘         └─────────────────────────┘     └──────────────┘ │
   └─────────────────────────────────────────────────────────────────────────────────────┘
```

### Supported NIST Post-Quantum Standards:
1. **NIST FIPS 203**: **ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism / Crystals-Kyber)
2. **NIST FIPS 204**: **ML-DSA** (Module-Lattice-Based Digital Signature Algorithm / Crystals-Dilithium)
3. **NIST FIPS 205**: **SLH-DSA** (Stateless Hash-Based Digital Signature Algorithm / SPHINCS+)
4. **Hybrid Transitions**: `X25519_Kyber768Draft00` / `ML-KEM-768` hybrid key exchange.

### 7-Phase Transition Roadmap Engine:
- **Phase A**: Discovery & Cryptographic Asset Inventory
- **Phase B**: Threat Modeling & HNDL Exposure Scoring
- **Phase C**: Protocol Capability & MTA Readiness Assessment
- **Phase D**: Hybrid Key Exchange Staging (X25519 + ML-KEM)
- **Phase E**: Pure Post-Quantum Pilot & Certificate Authority Upgrades
- **Phase F**: Legacy Deprecation & Plaintext Decommissioning
- **Phase G**: Continuous PQC Assurance & Posture Auditing

---

## 🔗 Blockchain-Backed Chain of Custody

To guarantee legal admissibility in judicial proceedings, SecureMailScope X incorporates a local, air-gapped cryptographic chain-of-custody engine.

```
                      ┌───────────────────────────────────────┐
                      │    Raw PCAP SHA-256 Ingestion Hash    │
                      └───────────────────┬───────────────────┘
                                          │
                                          ▼
                      ┌───────────────────────────────────────┐
                      │      Canonical Analysis Manifest      │
                      │  - Dissected Packet Count             │
                      │  - Verified STARTTLS State            │
                      │  - Security Findings Catalog          │
                      │  - TShark Engine Version (4.6+)       │
                      └───────────────────┬───────────────────┘
                                          │
                                          ▼
                      ┌───────────────────────────────────────┐
                      │          SHA-256 Merkle Tree          │
                      │ ┌───────────────┐   ┌───────────────┐ │
                      │ │ Hash(Packets) │   │ Hash(Findings)│ │
                      │ └───────┬───────┘   └───────┬───────┘ │
                      │         └─────────┬─────────┘         │
                      │                   ▼                   │
                      │             Merkle Root               │
                      └───────────────────┬───────────────────┘
                                          │
                                          ▼
                      ┌───────────────────────────────────────┐
                      │  Cryptographic Peer Sign-Off (M-of-N) │
                      │   - Ed25519 / RSA-PSS Signatures      │
                      │   - Lead Investigator Seal            │
                      │   - Self-Review Prevention Checks     │
                      └───────────────────────────────────────┘
```

---

## 🛠️ Remediation & Simulate-Fix Engine

SecureMailScope X does not just identify vulnerabilities—it provides verified, production-ready remediation configurations and allows security teams to simulate posture improvements before making live MTA changes.

### Supported Mail Transfer Agents (MTAs):
- **Postfix** (`main.cf`, `master.cf`)
- **Exim** (`exim4.conf`)
- **Dovecot** (`dovecot.conf`, `10-ssl.conf`)
- **Sendmail** (`sendmail.mc`)

```
   [DETECTED VULNERABILITY] ➔ SMTP STARTTLS Cleartext Fallback (Weak Ciphers)
              │
              ▼
   [ADVISORY PLAYBOOK GENERATED]
   ┌────────────────────────────────────────────────────────────────────────┐
   │ # Postfix Hardening Configuration (/etc/postfix/main.cf)              │
   │ smtpd_tls_security_level = encrypt                                    │
   │ smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1     │
   │ smtpd_tls_mandatory_ciphers = high                                    │
   │ smtpd_tls_mandatory_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4  │
   │ tls_preempt_cipherlist = yes                                          │
   └────────────────────────────────────────────────────────────────────────┘
              │
              ▼
   [IN-MEMORY SIMULATE-FIX] ➔ Projected CSPI: 62% (Grade D) ➔ 96% (Grade A+)
              │
              ▼
   [VERIFY-AFTER-FIX] ➔ Re-analyze new PCAP ➔ Validates compliance on-the-fly
```

---

## 💻 Tech Stack

```
Frontend:
  • Framework: React 18 with TypeScript
  • Build Tool: Vite
  • Styling: Tailwind CSS & Lucide Icons
  • State Management: Zustand (with local cache sanitization)
  • Charts: Recharts (Dynamic Posture & Radar Visualizations)

Backend:
  • Runtime: Python 3.10+ / 3.14 (Windows 11 x64 & Linux)
  • Framework: FastAPI 0.115+ (Pydantic V2 DTOs)
  • Packet Dissection: Wireshark / TShark Engine (Subprocess Stream IO)
  • Cryptography: Cryptography (Ed25519, RSA-PSS, SHA-256 Merkle Engine)
  • Database: SQLite (Zero-Configuration, Air-Gapped)
  • Reporting: ReportLab (Cryptographic Multi-Page PDF Generation)

SOC / SIEM Transports:
  • Formats: CEF (Common Event Format), RFC 5424 Syslog, Normalized JSON
  • Delivery: UDP Syslog, TCP Syslog, HTTPS Webhook
```

---

## 📁 Repository Structure

```
SecureMailScope X/
├── 📂 backend/                      # Python FastAPI Forensic Backend
│   ├── 📂 app/
│   │   ├── 📂 ai/                   # Explainable AI & CSPI Risk Models
│   │   ├── 📂 api/                  # REST Endpoints (v1: analyze, rules, rbac, siem)
│   │   ├── 📂 core/                 # Config, TShark Detectors & Security
│   │   ├── 📂 db/                   # SQLite Session & Schema Migrations
│   │   ├── 📂 forensic/             # Health, Confidence, PCAP Reader & Rule Engine
│   │   ├── 📂 ml/                   # ML Triage Models & Feature Extractors
│   │   ├── 📂 protocols/            # SMTP, IMAP, and POP3 Protocol Analyzers
│   │   ├── 📂 schemas/              # Pydantic DTOs (Forensic, RBAC, SIEM, PQC)
│   │   ├── 📂 services/             # Analysis, Custody, Remediation & PQC Services
│   │   └── 📂 tls/                  # TLS Handshake Dissector & IANA Cipher Catalog
│   ├── 📂 tests/                    # 541 Automated Test Cases (100% Pass)
│   └── 📄 main.py                   # FastAPI Application Entrypoint
├── 📂 frontend/                     # React 18 TypeScript Dashboard
│   ├── 📂 src/
│   │   ├── 📂 api/                  # Axios Client & Normalization Layer
│   │   ├── 📂 components/           # UI Components (KPI Cards, Charts, Layout)
│   │   ├── 📂 pages/                # 20 Interactive Workspaces & Pages
│   │   └── 📂 store/                # Zustand Forensic State Store
│   └── 📄 package.json              # Node Dependencies & Build Scripts
├── 📂 pcap_samples/                 # Verified Baseline Forensic Captures
│   ├── 📄 smtp-starttls-test.pcapng # Canonical SMTP 587 STARTTLS ➔ TLS 1.3
│   ├── 📄 imap-tls-test.pcapng      # Direct TLS IMAP 993
│   └── 📄 pop3-tls-test.pcapng      # Direct TLS POP3 995
├── 📄 ARCHITECTURE.md               # Complete System Architecture Specification
├── 📄 PROJECT_STATUS.md             # Verified Phase History (Phases 1–25)
├── 📄 INSTALL_WINDOWS.md            # Windows 11 Step-by-Step Installation
└── 📄 README.md                     # Master Documentation File
```

---

## 🚀 Installation & Quickstart

### 📋 Prerequisites
1. **Operating System**: Windows 11 / 10 x64, Ubuntu 22.04+, or macOS
2. **Python**: Version 3.10 to 3.14 (`python --version`)
3. **Node.js**: Version 18.0+ and npm (`node --version`)
4. **Wireshark / TShark**: Installed and available in PATH (e.g., `C:\Program Files\Wireshark\tshark.exe` or `/usr/bin/tshark`)

---

### Step 1: Clone Repository
```bash
git clone https://github.com/coderarghya-dev/SecureMailScope-X.git
cd "SecureMailScope X"
```

---

### Step 2: Backend Setup
```powershell
# Navigate to backend directory
cd backend

# Create and activate Python virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1    # On Linux/macOS: source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the FastAPI Server
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
*Backend runs at `http://127.0.0.1:8000`. Interactive OpenAPI documentation at `http://127.0.0.1:8000/docs`.*

---

### Step 3: Frontend Setup
```powershell
# Open a new terminal in the frontend directory
cd frontend

# Install dependencies
npm install

# Start Vite Development Server
npm run dev
```
*Dashboard will open at `http://localhost:5173`.*

---

### Step 4: Run Test Suites (541 Tests)
```powershell
# Run backend test suite
python -m unittest discover -s backend/tests -p "test_*.py"
```

```
....................................................................................................
----------------------------------------------------------------------
Ran 541 tests in 12.841s

OK (541/541 Tests Passed)
```

---

## 🌐 REST API Reference

The backend exposes strongly typed REST endpoints documented via OpenAPI 3.1:

```
┌────────┬───────────────────────────────────────┬────────────────────────────────────────────┐
│ Method │ Endpoint                              │ Description                                │
├────────┼───────────────────────────────────────┼────────────────────────────────────────────┤
│ GET    │ /api/v1/health                        │ System health, TShark detector diagnostic  │
│ POST   │ /api/v1/analyze                       │ Upload & passively dissect .pcap/.pcapng   │
│ GET    │ /api/v1/analyze/{analysis_id}         │ Get full forensic analysis report by ID    │
│ GET    │ /api/v1/analyses/{id}/sessions        │ List reconstructed SMTP/IMAP/POP3 sessions │
│ GET    │ /api/v1/analyses/{id}/packets         │ Query native packet evidence & payloads    │
│ GET    │ /api/v1/analyses/{id}/custody         │ Retrieve Merkle tree & custody record      │
│ POST   │ /api/v1/rbac/reviews                  │ Submit Ed25519/RSA-PSS M-of-N sign-off     │
│ GET    │ /api/v1/pqc/roadmaps/{id}             │ Generate NIST PQC 7-phase transition plan  │
│ GET    │ /api/v1/remediation/playbooks         │ Fetch Postfix/Exim/Dovecot playbooks       │
│ POST   │ /api/v1/remediation/simulate         │ In-memory what-if risk posture projection  │
│ POST   │ /api/v1/monitoring/scan               │ Execute active scan with DNS/SSRF defense  │
│ POST   │ /api/v1/siem/export                   │ Export telemetry in CEF, Syslog, or JSON   │
│ GET    │ /api/v1/reports/{id}/pdf              │ Download cryptographic PDF audit report    │
└────────┴───────────────────────────────────────┴────────────────────────────────────────────┘
```

---

## 🏆 Competition Demo Workflow

### Canonical Demo Capture: `smtp-starttls-test.pcapng`
- **Protocol**: SMTP (Port 587)
- **Raw PCAP Frame Count**: 4,309 frames
- **Reconstructed SMTP Stream**: 27 packets (Stream 17)
- **Native Evidence Frames**:
  - `Frame 2291`: 220 Server STARTTLS Capability Advertisement
  - `Frame 2292`: Client STARTTLS Command Request
  - `Frame 2294`: 220 2.0.0 Ready to start TLS (Accepted)
  - `Frame 2295`: TLS 1.3 ClientHello (Offers, SNI, KeyShares)
  - `Frame 2298`: TLS 1.3 ServerHello (`TLS_AES_256_GCM_SHA384`)
  - `Frames 2300+`: Protected Encrypted Application Data Records
- **Authoritative Metrics**:
  - **Evidence Confidence**: `95% (HIGH)`
  - **Capture Health Score**: `100 / 100`
  - **PQC / HNDL Assessment**: Incomplete evidence-bounded assessment (No post-quantum key-exchange observed in classical session).

---

## 🛡️ Security & Compliance Standards

- **RFC 3207**: SMTP Service Extension for Secure SMTP over TLS
- **RFC 8446**: The Transport Layer Security (TLS) Protocol Version 1.3
- **NIST SP 800-52 Rev. 2**: Guidelines for TLS Implementations
- **NIST FIPS 203 / 204 / 205**: Post-Quantum Cryptography Standards
- **ISO/IEC 27037**: Guidelines for Identification, Collection, Acquisition and Preservation of Digital Evidence

---

## 👥 Contributors & Acknowledgements

Developed for **Smart India Hackathon 2026** (Problem Statement: **SIH26159**).

- **Team**: SecureMailScope X Core Engineering Group
- **Lead Developer**: [@coderarghya-dev](https://github.com/coderarghya-dev)

---

<div align="center">
  <sub>Built with ❤️ for Cyber Defense & Next-Gen Cryptographic Forensics • SecureMailScope X © 2026</sub>
</div>
