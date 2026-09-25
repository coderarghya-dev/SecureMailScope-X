# SecureMailScope X

> **Explainable AI-Driven Email Cryptographic Forensics with Post-Quantum Readiness and Blockchain-Backed Chain of Custody**  
> *Problem Statement:* SIH26159 | Smart India Hackathon 2026

---

## 1. Project Overview

SecureMailScope X is a local, high-precision cybersecurity forensics platform designed to passively analyze `.pcap` and `.pcapng` network captures containing email protocols (**SMTP**, **IMAP**, **POP3**).

The system reconstructs TCP sessions, tracks protocol command state machines, audits STARTTLS transitions and direct TLS sessions, extracts cryptographic parameters, and evaluates security posture strictly from packet evidence.

### Core Forensic Philosophy
$$\text{Raw PCAP} \longrightarrow \text{Forensic Evidence} \longrightarrow \text{Security Analysis} \longrightarrow \text{Explainable AI (CSPI)} \longrightarrow \text{PQC Readiness} \longrightarrow \text{Remediation} \longrightarrow \text{Blockchain Integrity}$$

- **Zero Fake Data**: Every finding is backed by frame numbers, timestamps, and packet payloads.
- **TLS 1.3 Honesty**: Certificate invisibility due to TLS 1.3 encrypted handshakes is accurately reported rather than fabricated.
- **Local Execution**: Completely offline and self-contained; no cloud API dependencies.

---

## 2. Milestone 1 Architecture

```
d:\SecureMailScope X\
├── backend/
│   ├── app/
│   │   ├── core/
│   │   │   └── tshark_detector.py      # TShark executable discovery
│   │   ├── forensic/
│   │   │   ├── pcap_reader.py          # TShark field streaming & packet extraction
│   │   │   └── session_reconstructor.py# TCP stream grouping & state machine
│   │   ├── protocols/
│   │   │   ├── smtp_analyzer.py        # EHLO/HELO, banner, STARTTLS state tracker
│   │   │   └── imap_analyzer.py        # Direct TLS vs STARTTLS discriminator
│   │   ├── tls/
│   │   │   ├── tls_dissector.py        # Client/Server Hello, version & SNI dissector
│   │   │   └── cipher_suites.py        # IANA database, PFS, strength, PQC flags
│   │   └── schemas/
│   │       └── forensic.py             # Data models for sessions & evidence
│   ├── tests/
│   │   └── test_smtp_starttls.py       # Automated unit test suite
│   ├── run_parser.py                   # Standalone CLI forensics engine
│   └── requirements.txt
└── README.md
```

---

## 3. Running the Forensics Engine

### Prerequisites
- Python 3.10+ (detected: Python 3.14.3)
- Wireshark / TShark installed (detected: `C:\Program Files\Wireshark\tshark.exe`)

### Execution Command
Run the forensic parser directly against any capture:
```powershell
python backend/run_parser.py "D:\SecureMailScope\pcap_samples\smtp-starttls-test.pcapng"
```

To export structured forensic JSON:
```powershell
python backend/run_parser.py "D:\SecureMailScope\pcap_samples\smtp-starttls-test.pcapng" --json
```

### Running the Test Suite
```powershell
python backend/tests/test_smtp_starttls.py
```
