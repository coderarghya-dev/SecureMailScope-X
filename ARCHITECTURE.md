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
