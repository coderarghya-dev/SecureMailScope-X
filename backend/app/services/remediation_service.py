# ==============================================================================
# SecureMailScope X — Phase 23: Remediation Playbooks & Simulate-Fix Service
# ==============================================================================
"""Service engine providing evidence-based remediation playbooks, platform-specific
hardening snippets (Postfix, Exim, Dovecot, Sendmail, Generic), deterministic
simulate-fix risk projections, and verify-after-fix forensic workflows.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from app.db.database import get_db_connection
from app.db.repository import ForensicRepository
from app.forensic.remediation_simulator import RemediationSimulator, SUPPORTED_REMEDIATIONS
from app.schemas.identity import ActorContext
from app.schemas.remediation import (
    MarkAppliedRequest,
    PlaybookGenerationRequest,
    PlaybookGenerationResponse,
    PostureLabel,
    RemediationCategory,
    RemediationGuidanceItem,
    RemediationPlan,
    RemediationPlanCreateRequest,
    RemediationPlanItem,
    RemediationPlanUpdateRequest,
    RemediationPlatform,
    RemediationPriority,
    RemediationStatus,
    SimulateFixRequest,
    SimulateFixResponse,
    VerificationMethod,
    VerificationRecord,
    VerificationRequest,
    VerificationStatus,
)


# Standard Playbook Knowledge Base for supported platforms
PLAYBOOK_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "DEPRECATED_TLS": {
        "finding_codes": ["TLS_1_0_ENABLED", "TLS_1_1_ENABLED", "DEPRECATED_TLS_DETECTED", "DEPRECATED-TLS", "TLS-1-0", "TLS-1-1"],
        "remediation_id": "DISABLE_DEPRECATED_TLS",
        "action_title": "Disable Deprecated TLS 1.0 & TLS 1.1 Protocols",
        "category": RemediationCategory.TLS_CONFIGURATION,
        "priority": RemediationPriority.CRITICAL,
        "expected_security_effect": "Eliminates protocol downgrade attacks (POODLE, BEAST) and mandates modern TLS 1.2 / TLS 1.3.",
        "validation_steps": [
            "Execute active scan or 'openssl s_client -connect <host>:<port> -tls1' to verify handshake rejection.",
            "Verify with '-tls1_1' that connection is refused.",
            "Verify with '-tls1_2' and '-tls1_3' that handshake completes successfully."
        ],
        "rollback_guidance": "If legacy client disconnection occurs, temporarily restore TLS 1.2 fallback while transitioning clients.",
        "assumptions": ["Server TLS library (OpenSSL/GnuTLS) supports TLS 1.2+.", "No legacy mail clients require TLS 1.0."],
        "limitations": ["Requires service reload/restart.", "Does not upgrade underlying OS crypto libraries."],
        "snippets": {
            RemediationPlatform.POSTFIX: (
                "# /etc/postfix/main.cf\n"
                "smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\n"
                "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\n"
                "smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\n"
                "smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\n"
                "smtpd_tls_security_level = may\n"
                "# Execute: postfix reload"
            ),
            RemediationPlatform.EXIM: (
                "# /etc/exim4/exim4.conf.template\n"
                "tls_require_ciphers = DEFAULT:!SSLv2:!SSLv3:!TLSv1:!TLSv1.1\n"
                "openssl_options = +no_sslv2 +no_sslv3 +no_tlsv1 +no_tlsv1_1\n"
                "# Execute: update-exim4.conf && systemctl restart exim4"
            ),
            RemediationPlatform.DOVECOT: (
                "# /etc/dovecot/conf.d/10-ssl.conf\n"
                "ssl = required\n"
                "ssl_min_protocol = TLSv1.2\n"
                "# Execute: systemctl reload dovecot"
            ),
            RemediationPlatform.SENDMAIL: (
                "# /etc/mail/sendmail.mc\n"
                "LOCAL_CONFIG\n"
                "O CipherList=HIGH:!aNULL:!MD5:!3DES:!CAMELLIA:!PSK:!SRP\n"
                "O ServerSSLOptions=+SSL_OP_NO_SSLv2 +SSL_OP_NO_SSLv3 +SSL_OP_NO_TLSv1 +SSL_OP_NO_TLSv1_1\n"
                "O ClientSSLOptions=+SSL_OP_NO_SSLv2 +SSL_OP_NO_SSLv3 +SSL_OP_NO_TLSv1 +SSL_OP_NO_TLSv1_1\n"
                "# Execute: make -C /etc/mail && systemctl restart sendmail"
            ),
            RemediationPlatform.GENERIC: (
                "# Generic MTA / Mail Proxy Guidance (RFC 8996 / NIST SP 800-52r2)\n"
                "1. Restrict minimum protocol to TLS 1.2 (0x0303) or TLS 1.3 (0x0304).\n"
                "2. Explicitly disable SSLv2 (0x0200), SSLv3 (0x0300), TLSv1.0 (0x0301), and TLSv1.1 (0x0302).\n"
                "3. Verify client compatibility matrix before disabling TLS 1.2."
            ),
        },
    },
    "WEAK_CIPHERS": {
        "finding_codes": ["WEAK_CIPHER", "INSECURE_CIPHER_SUITE", "DEPRECATED-CIPHER", "CIPHER-CBC", "CIPHER-RC4", "CIPHER-3DES", "3DES", "RC4"],
        "remediation_id": "REPLACE_WEAK_CIPHER",
        "action_title": "Hardening Cipher Suites to AEAD & Secure Ciphers",
        "category": RemediationCategory.CIPHER_SUITE,
        "priority": RemediationPriority.HIGH,
        "expected_security_effect": "Mitigates SWEET32, RC4 bias, and CBC padding oracle attacks by enforcing AES-GCM and CHACHA20-POLY1305.",
        "validation_steps": [
            "Run cipher audit scan with testssl.sh or active probe.",
            "Verify weak ciphers (3DES, RC4, CBC) are rejected."
        ],
        "rollback_guidance": "Restore previous cipher string if critical legacy MTAs cannot negotiate connection.",
        "assumptions": ["MTA TLS stack supports modern AEAD ciphers."],
        "limitations": ["Old clients without ECDHE/AEAD support may fail handshake."],
        "snippets": {
            RemediationPlatform.POSTFIX: (
                "# /etc/postfix/main.cf\n"
                "smtpd_tls_mandatory_ciphers = high\n"
                "smtpd_tls_ciphers = high\n"
                "smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, aECDH, EDH-DSS-DES-CBC3-SHA, EDH-RSA-DES-CBC3-SHA, KRB5-DES, CBC3\n"
                "tls_high_cipherlist = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305\n"
                "# Execute: postfix reload"
            ),
            RemediationPlatform.EXIM: (
                "# /etc/exim4/exim4.conf.template\n"
                "tls_require_ciphers = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305\n"
                "# Execute: update-exim4.conf && systemctl restart exim4"
            ),
            RemediationPlatform.DOVECOT: (
                "# /etc/dovecot/conf.d/10-ssl.conf\n"
                "ssl_cipher_list = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305\n"
                "ssl_prefer_server_ciphers = yes\n"
                "# Execute: systemctl reload dovecot"
            ),
            RemediationPlatform.SENDMAIL: (
                "# /etc/mail/sendmail.mc\n"
                "LOCAL_CONFIG\n"
                "O CipherList=HIGH:!aNULL:!MD5:!3DES:!CAMELLIA:!PSK:!SRP:!DES:!RC4\n"
                "# Execute: make -C /etc/mail && systemctl restart sendmail"
            ),
            RemediationPlatform.GENERIC: (
                "# Generic Cipher Hardening (Mozilla Modern / Intermediate)\n"
                "CipherList: ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384\n"
                "Ensure server cipher preference is enabled."
            ),
        },
    },
    "STARTTLS_ENFORCEMENT": {
        "finding_codes": ["STARTTLS_NOT_OFFERED", "STARTTLS_DROPPED", "PLAINTEXT", "CLEAR-TEXT", "UNENCRYPTED", "STRIPPING", "STARTTLS-STRIPPING"],
        "remediation_id": "REQUIRE_STARTTLS",
        "action_title": "Enforce STARTTLS & Transport Encryption",
        "category": RemediationCategory.STARTTLS,
        "priority": RemediationPriority.CRITICAL,
        "expected_security_effect": "Prevents passive eavesdropping and man-in-the-middle STARTTLS stripping attacks.",
        "validation_steps": [
            "Connect via telnet/nc and verify '250-STARTTLS' is present in EHLO response.",
            "Verify sending STARTTLS transitions immediately to TLS handshake."
        ],
        "rollback_guidance": "If upstream MTAs fail to deliver, switch to opportunistic STARTTLS ('may') while diagnosing.",
        "assumptions": ["Valid X.509 certificate and private key are installed on server."],
        "limitations": ["Opportunistic STARTTLS still allows fallback unless MTA-STS/DANE is enforced."],
        "snippets": {
            RemediationPlatform.POSTFIX: (
                "# /etc/postfix/main.cf\n"
                "smtpd_tls_security_level = may\n"
                "smtpd_tls_auth_only = yes\n"
                "smtpd_tls_cert_file = /etc/ssl/certs/mailserver.crt\n"
                "smtpd_tls_key_file = /etc/ssl/private/mailserver.key\n"
                "smtpd_tls_loglevel = 1\n"
                "# Execute: postfix reload"
            ),
            RemediationPlatform.EXIM: (
                "# /etc/exim4/exim4.conf.template\n"
                "tls_advertise_hosts = *\n"
                "tls_certificate = /etc/ssl/certs/mailserver.crt\n"
                "tls_privatekey = /etc/ssl/private/mailserver.key\n"
                "auth_advertise_hosts = ${if eq{$tls_cipher}{}{}{*}}\n"
                "# Execute: update-exim4.conf && systemctl restart exim4"
            ),
            RemediationPlatform.DOVECOT: (
                "# /etc/dovecot/conf.d/10-ssl.conf\n"
                "ssl = required\n"
                "disable_plaintext_auth = yes\n"
                "ssl_cert = </etc/ssl/certs/mailserver.crt\n"
                "ssl_key = </etc/ssl/private/mailserver.key\n"
                "# Execute: systemctl reload dovecot"
            ),
            RemediationPlatform.SENDMAIL: (
                "# /etc/mail/sendmail.mc\n"
                "define(`confCACERT_PATH', `/etc/ssl/certs')dnl\n"
                "define(`confCACERT', `/etc/ssl/certs/ca-certificates.crt')dnl\n"
                "define(`confSERVER_CERT', `/etc/ssl/certs/mailserver.crt')dnl\n"
                "define(`confSERVER_KEY', `/etc/ssl/private/mailserver.key')dnl\n"
                "define(`confTLS_OPTIONS', `+SSL_OP_NO_SSLv2 +SSL_OP_NO_SSLv3')dnl\n"
                "# Execute: make -C /etc/mail && systemctl restart sendmail"
            ),
            RemediationPlatform.GENERIC: (
                "# Generic STARTTLS Hardening (RFC 3207 / RFC 8314)\n"
                "1. Advertise STARTTLS in response to EHLO.\n"
                "2. Require TLS before permitting AUTH / authentication commands.\n"
                "3. Ensure valid certificate chain is bound."
            ),
        },
    },
    "CERTIFICATE_RENEWAL": {
        "finding_codes": ["CERT_EXPIRED", "CERTIFICATE_EXPIRED", "NOT-YET-VALID", "EXPIRING-SOON", "SELF_SIGNED_CERT", "UNTRUSTED_ROOT"],
        "remediation_id": "RENEW_CERTIFICATE",
        "action_title": "Renew & Replace X.509 Mail Server Certificate",
        "category": RemediationCategory.CERTIFICATE,
        "priority": RemediationPriority.HIGH,
        "expected_security_effect": "Restores cryptographic authenticity and trust chain validation for connecting MTAs and clients.",
        "validation_steps": [
            "Check certificate expiry with 'openssl x509 -enddate -noout -in <cert>'.",
            "Verify issuer chain resolves to trusted root store."
        ],
        "rollback_guidance": "Keep backup of previous key/cert pair in secure local directory during deployment.",
        "assumptions": ["DNS names in SAN match mail hostname and MX records."],
        "limitations": ["Certificate issuance depends on external CA / ACME provider."],
        "snippets": {
            RemediationPlatform.POSTFIX: (
                "# Using Certbot / ACME for Postfix\n"
                "certbot certonly --standalone -d mail.example.com\n"
                "# /etc/postfix/main.cf\n"
                "smtpd_tls_cert_file = /etc/letsencrypt/live/mail.example.com/fullchain.pem\n"
                "smtpd_tls_key_file = /etc/letsencrypt/live/mail.example.com/privkey.pem\n"
                "# Execute: postfix reload"
            ),
            RemediationPlatform.EXIM: (
                "# /etc/exim4/exim4.conf.template\n"
                "tls_certificate = /etc/letsencrypt/live/mail.example.com/fullchain.pem\n"
                "tls_privatekey = /etc/letsencrypt/live/mail.example.com/privkey.pem\n"
                "# Execute: update-exim4.conf && systemctl restart exim4"
            ),
            RemediationPlatform.DOVECOT: (
                "# /etc/dovecot/conf.d/10-ssl.conf\n"
                "ssl_cert = </etc/letsencrypt/live/mail.example.com/fullchain.pem\n"
                "ssl_key = </etc/letsencrypt/live/mail.example.com/privkey.pem\n"
                "# Execute: systemctl reload dovecot"
            ),
            RemediationPlatform.SENDMAIL: (
                "# /etc/mail/sendmail.mc\n"
                "define(`confSERVER_CERT', `/etc/letsencrypt/live/mail.example.com/cert.pem')dnl\n"
                "define(`confSERVER_KEY', `/etc/letsencrypt/live/mail.example.com/privkey.pem')dnl\n"
                "define(`confCACERT', `/etc/letsencrypt/live/mail.example.com/chain.pem')dnl\n"
                "# Execute: make -C /etc/mail && systemctl restart sendmail"
            ),
            RemediationPlatform.GENERIC: (
                "# Generic Certificate Renewal Steps\n"
                "1. Generate new 2048/4096-bit RSA or P-256 ECDSA CSR.\n"
                "2. Obtain signed certificate from trusted Public CA or Enterprise PKI.\n"
                "3. Deploy fullchain bundle and private key to server paths.\n"
                "4. Reload MTA service."
            ),
        },
    },
    "FORWARD_SECRECY": {
        "finding_codes": ["PFS_NOT_SUPPORTED", "NO_PFS", "NO-FORWARD-SECRECY", "STATIC-RSA", "STATIC_RSA"],
        "remediation_id": "ENABLE_FORWARD_SECRECY",
        "action_title": "Enable Perfect Forward Secrecy (ECDHE / DHE)",
        "category": RemediationCategory.PFS,
        "priority": RemediationPriority.HIGH,
        "expected_security_effect": "Protects historical encrypted session traffic from retrospective decryption if private key is compromised.",
        "validation_steps": [
            "Test handshake with 'openssl s_client -connect <host>:<port> -starttls smtp'.",
            "Verify 'Server Temp Key: ECDH' or 'X25519' is negotiated."
        ],
        "rollback_guidance": "Ensure DH parameter configuration does not exceed CPU constraints on low-end servers.",
        "assumptions": ["OpenSSL version >= 1.0.2 with ECC curve support."],
        "limitations": ["Requires client support for ECDHE or DHE key exchange."],
        "snippets": {
            RemediationPlatform.POSTFIX: (
                "# /etc/postfix/main.cf\n"
                "smtpd_tls_eecdh_grade = strong\n"
                "smtpd_tls_dh1024_param_file = /etc/postfix/dh2048.pem\n"
                "# Generate DH params: openssl dhparam -out /etc/postfix/dh2048.pem 2048\n"
                "# Execute: postfix reload"
            ),
            RemediationPlatform.EXIM: (
                "# /etc/exim4/exim4.conf.template\n"
                "tls_dhparam = /etc/exim4/dh2048.pem\n"
                "tls_require_ciphers = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384\n"
                "# Execute: update-exim4.conf && systemctl restart exim4"
            ),
            RemediationPlatform.DOVECOT: (
                "# /etc/dovecot/conf.d/10-ssl.conf\n"
                "ssl_dh = </etc/dovecot/dh.pem\n"
                "ssl_prefer_server_ciphers = yes\n"
                "# Generate: openssl dhparam -out /etc/dovecot/dh.pem 2048\n"
                "# Execute: systemctl reload dovecot"
            ),
            RemediationPlatform.SENDMAIL: (
                "# /etc/mail/sendmail.mc\n"
                "define(`confDH_PARAMETERS', `/etc/mail/certs/dh2048.pem')dnl\n"
                "# Execute: make -C /etc/mail && systemctl restart sendmail"
            ),
            RemediationPlatform.GENERIC: (
                "# Generic Forward Secrecy Guidance\n"
                "1. Enforce ephemeral ECDHE curves (X25519, secp256r1, secp384r1).\n"
                "2. Provide >= 2048-bit Diffie-Hellman parameters if DHE is supported.\n"
                "3. Deprecate static RSA key exchange cipher suites (TLS_RSA_*)."
            ),
        },
    },
    "EMAIL_AUTH": {
        "finding_codes": ["DMARC_POLICY_NONE", "DMARC-POLICY-NONE", "DMARC-POLICY-ABSENT", "MISSING_SPF", "SPF-POLICY-ABSENT", "MISSING_DKIM", "DMARC_NONE"],
        "remediation_id": "ENABLE_DMARC_POLICY",
        "action_title": "Enforce DMARC, SPF, and DKIM Domain Protections",
        "category": RemediationCategory.EMAIL_AUTHENTICATION,
        "priority": RemediationPriority.HIGH,
        "expected_security_effect": "Blocks domain spoofing and phishing by mandating cryptographic sender verification.",
        "validation_steps": [
            "Query DNS: 'dig TXT _dmarc.<domain>' and 'dig TXT <domain>'.",
            "Verify DMARC tag 'p=quarantine' or 'p=reject' is published."
        ],
        "rollback_guidance": "Temporarily revert DMARC to 'p=none' if legitimate transactional mail is rejected.",
        "assumptions": ["All authorized sending IP addresses and third-party senders are identified in SPF."],
        "limitations": ["DNS propagation delays apply.", "Requires coordination across all mail delivery services."],
        "snippets": {
            RemediationPlatform.POSTFIX: (
                "# DNS Resource Records for Example Domain:\n"
                "_dmarc.example.com. IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com; pct=100\"\n"
                "example.com.        IN TXT \"v=spf1 mx ip4:192.0.2.1 -all\"\n"
                "# Install OpenDKIM / OpenDMARC milters for inbound verification in /etc/postfix/main.cf:\n"
                "smtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:8893\n"
                "non_smtpd_milters = $smtpd_milters"
            ),
            RemediationPlatform.EXIM: (
                "# DNS Resource Records:\n"
                "_dmarc.example.com. IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com; pct=100\"\n"
                "example.com.        IN TXT \"v=spf1 mx ip4:192.0.2.1 -all\"\n"
                "# Enable SPF/DKIM validation in Exim ACLs."
            ),
            RemediationPlatform.DOVECOT: (
                "# Dovecot (Inbound delivery / Sieve / Spam filtering integration)\n"
                "# Publish domain TXT records at DNS provider:\n"
                "_dmarc.example.com. IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com; pct=100\""
            ),
            RemediationPlatform.SENDMAIL: (
                "# Sendmail (milter-opendkim / milter-opendmarc)\n"
                "INPUT_MAIL_FILTER(`opendkim', `S=inet:8891@localhost')\n"
                "INPUT_MAIL_FILTER(`opendmarc', `S=inet:8893@localhost')"
            ),
            RemediationPlatform.GENERIC: (
                "# Generic DNS Authentication Records (RFC 7489 / RFC 7208 / RFC 6376)\n"
                "1. Publish SPF record: 'v=spf1 <authorized-sources> -all'\n"
                "2. Publish DKIM public keys under selector subdomains.\n"
                "3. Publish DMARC record: 'v=DMARC1; p=quarantine; rua=mailto:...; pct=100'"
            ),
        },
    },
    "MODERN_TLS": {
        "finding_codes": [
            "TLS_1_3_NEGOTIATED",
            "FINDING-TLS-1.3-NEGOTIATED",
            "TLS-1-3",
            "TLS13",
            "TLS_1_3",
            "MODERN_TLS",
            "STATE-OF-THE-ART TLS 1.3 NEGOTIATED",
        ],
        "remediation_id": "MAINTAIN_MODERN_TLS",
        "action_title": "Maintain Modern TLS 1.3 Transport Configuration",
        "category": RemediationCategory.TLS_CONFIGURATION,
        "priority": RemediationPriority.INFORMATIONAL,
        "expected_security_effect": "Preserves state-of-the-art TLS 1.3 transport encryption, AEAD cipher integrity, and forward secrecy.",
        "validation_steps": [
            "Verify MTA actively offers TLS 1.3 cipher suites (TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256).",
            "Ensure forward secrecy and 0-RTT anti-replay controls remain active."
        ],
        "rollback_guidance": "No rollback needed; maintain TLS 1.3 as prioritized protocol.",
        "assumptions": ["MTA and client crypto libraries support TLS 1.3 (RFC 8446)."],
        "limitations": ["Legacy clients without TLS 1.3 negotiate TLS 1.2 if permitted."],
        "snippets": {
            RemediationPlatform.POSTFIX: (
                "# /etc/postfix/main.cf\n"
                "smtpd_tls_mandatory_protocols = >=TLSv1.2\n"
                "smtpd_tls_protocols = >=TLSv1.2\n"
                "tls_high_cipherlist = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256\n"
                "# Execute: postfix reload"
            ),
            RemediationPlatform.EXIM: (
                "# /etc/exim4/exim4.conf.template\n"
                "openssl_options = +no_sslv2 +no_sslv3 +no_tlsv1 +no_tlsv1_1\n"
                "# Execute: update-exim4.conf && systemctl restart exim4"
            ),
            RemediationPlatform.DOVECOT: (
                "# /etc/dovecot/conf.d/10-ssl.conf\n"
                "ssl_min_protocol = TLSv1.2\n"
                "# Execute: systemctl reload dovecot"
            ),
            RemediationPlatform.SENDMAIL: (
                "# /etc/mail/sendmail.mc\n"
                "O ServerSSLOptions=+SSL_OP_NO_SSLv2 +SSL_OP_NO_SSLv3 +SSL_OP_NO_TLSv1 +SSL_OP_NO_TLSv1_1"
            ),
            RemediationPlatform.GENERIC: (
                "# Generic TLS 1.3 Guidance (RFC 8446)\n"
                "1. Enforce TLS 1.3 support across all MTA endpoints.\n"
                "2. Maintain TLS 1.2 compatibility with AEAD ciphers for transitional clients."
            ),
        },
    },
    "PQC_MIGRATION": {
        "finding_codes": [
            "PQC_NON_COMPLIANT",
            "PQC_VULNERABLE",
            "PQC-CLASSICAL-KEX",
            "HNDL-RISK",
            "PQC-READINESS",
            "FINDING-PQC-CLASSICAL-KEX-EXPOSURE",
            "PQC_HARVEST_NOW_DECRYPT_LATER",
            "HNDL_EXPOSURE",
            "HNDL",
            "VULNERABLE TO HARVEST NOW, DECRYPT LATER (HNDL)",
        ],
        "remediation_id": "ENABLE_HYBRID_PQC",
        "action_title": "Deploy Post-Quantum Hybrid Key Exchange (ML-KEM / X25519Kyber768)",
        "category": RemediationCategory.PQC_MIGRATION,
        "priority": RemediationPriority.MEDIUM,
        "expected_security_effect": "Protects against 'Harvest Now, Decrypt Later' (HNDL) attacks by deploying quantum-resistant key encapsulation.",
        "validation_steps": [
            "Test with PQC-capable client (OpenSSL 3.2+ or OQS): 'openssl s_client -groups X25519MLKEM768:X25519Kyber768Draft00 -connect <host>:<port>'.",
            "Verify PQC key share is negotiated."
        ],
        "rollback_guidance": "Retain classical ECDHE in hybrid preference list to prevent legacy client failure.",
        "assumptions": ["MTA crypto library compiled with OpenSSL 3.2+ or liboqs module."],
        "limitations": ["Standardized FIPS 203 support depends on upstream OS package updates."],
        "snippets": {
            RemediationPlatform.POSTFIX: (
                "# Postfix with OpenSSL 3.2+ / Post-Quantum TLS 1.3 Groups\n"
                "# /etc/postfix/main.cf\n"
                "tls_high_cipherlist = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\n"
                "# Ensure OpenSSL config (/etc/ssl/openssl.cnf) includes Groups = X25519MLKEM768:x25519_kyber768:X25519:P-256\n"
                "# Execute: postfix reload"
            ),
            RemediationPlatform.EXIM: (
                "# /etc/exim4/exim4.conf.template\n"
                "# Configure OpenSSL 3.2 groups via system crypto policy or openssl.cnf\n"
                "# Groups = X25519MLKEM768:x25519_kyber768:X25519:P-256"
            ),
            RemediationPlatform.DOVECOT: (
                "# Dovecot (OpenSSL 3.2+ SSL Groups)\n"
                "# /etc/dovecot/conf.d/10-ssl.conf\n"
                "ssl_min_protocol = TLSv1.3\n"
                "# Handled by system OpenSSL 3.2 provider"
            ),
            RemediationPlatform.SENDMAIL: (
                "# Sendmail (OpenSSL 3.2+ Integration)\n"
                "O ServerSSLOptions=+SSL_OP_NO_SSLv2 +SSL_OP_NO_SSLv3 +SSL_OP_NO_TLSv1 +SSL_OP_NO_TLSv1_1"
            ),
            RemediationPlatform.GENERIC: (
                "# Generic Post-Quantum Hybrid Migration (NIST FIPS 203 / RFC 9180)\n"
                "1. Upgrade OpenSSL to version 3.2 or later.\n"
                "2. Enable hybrid key exchange groups: X25519MLKEM768 or SecP256r1MLKEM768.\n"
                "3. Maintain classical fallback for backward compatibility."
            ),
        },
    },
}


class RemediationService:
    """Core service implementing evidence-based remediation playbooks and verify-after-fix engine."""

    @classmethod
    def generate_playbook(
        cls,
        request: PlaybookGenerationRequest,
        user_id: Optional[str] = None,
        db_path: Optional[str] = None,
    ) -> PlaybookGenerationResponse:
        """
        Deterministically generates an evidence-linked remediation playbook for the requested
        platform and findings without running any live shell commands.
        """
        finding_codes: Set[str] = set()

        if request.finding_codes:
            finding_codes.update(c.upper() for c in request.finding_codes)

        # If analysis_id is provided, extract verified finding IDs with user isolation check
        if request.analysis_id:
            if user_id and not ForensicRepository.is_analysis_owned_by_user(user_id, request.analysis_id, db_path=db_path):
                raise ValueError(f"Analysis '{request.analysis_id}' not found in user workspace.")
            conn = get_db_connection(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT finding_id, rule_id, title FROM findings WHERE analysis_id = ?;", (request.analysis_id,))
            rows = cursor.fetchall()
            conn.close()
            # If finding_codes was not explicitly provided, populate from analysis findings
            if not request.finding_codes:
                for r in rows:
                    if r["finding_id"]:
                        finding_codes.add(r["finding_id"].upper())
                    if r["rule_id"]:
                        finding_codes.add(r["rule_id"].upper())
                    if r["title"]:
                        finding_codes.add(r["title"].upper())

        # If target_id is provided, extract posture snapshot drift or findings
        if request.target_id:
            conn = get_db_connection(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT drift_type FROM posture_drift_events WHERE target_id = ? ORDER BY detected_at DESC LIMIT 20;", (request.target_id,))
            rows = cursor.fetchall()
            conn.close()
            for r in rows:
                if r["drift_type"]:
                    finding_codes.add(r["drift_type"].upper())

        items: List[RemediationGuidanceItem] = []
        matched_templates: Set[str] = set()

        # Match findings to playbooks
        for template_key, tmpl in PLAYBOOK_TEMPLATES.items():
            tmpl_codes = [c.upper() for c in tmpl["finding_codes"]]
            # Check if any finding code matches
            matches = any(
                fc in tmpl_codes or any(tc in fc for tc in tmpl_codes)
                for fc in finding_codes
            )
            # If no finding codes specified at all and no analysis_id, return all catalog templates
            if (not finding_codes and not request.analysis_id) or matches:
                matched_templates.add(template_key)
                snippets_dict = tmpl["snippets"]
                snippet = snippets_dict.get(request.platform, snippets_dict.get(RemediationPlatform.GENERIC, ""))
                
                # Match specific finding code or default
                matched_fc = "GENERAL_SECURITY_HARDENING"
                for fc in finding_codes:
                    if fc in tmpl_codes or any(tc in fc for tc in tmpl_codes):
                        matched_fc = fc
                        break

                items.append(
                    RemediationGuidanceItem(
                        remediation_id=tmpl["remediation_id"],
                        finding_code=matched_fc,
                        action_title=tmpl["action_title"],
                        category=tmpl["category"],
                        priority=tmpl["priority"],
                        platform=request.platform,
                        guidance_text=f"Advisory hardening guidance for {request.platform.value} mail service.",
                        config_snippet=snippet,
                        expected_security_effect=tmpl["expected_security_effect"],
                        validation_steps=tmpl["validation_steps"],
                        rollback_guidance=tmpl["rollback_guidance"],
                        assumptions=tmpl["assumptions"],
                        limitations=tmpl["limitations"],
                    )
                )

        now_iso = datetime.now(timezone.utc).isoformat()
        return PlaybookGenerationResponse(
            platform=request.platform,
            total_recommendations=len(items),
            items=items,
            generated_at=now_iso,
        )

    @classmethod
    def simulate_fixes(
        cls,
        request: SimulateFixRequest,
        db_path: Optional[str] = None,
    ) -> SimulateFixResponse:
        """
        Calculates deterministic projected risk posture under hypothetical fixes.
        Preserves observed forensic evidence and explicitly labels posture states.
        """
        # Retrieve authoritative session or construct from analysis
        session = None
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        if request.session_id:
            cursor.execute("SELECT session_result_json FROM sessions WHERE session_id = ?;", (request.session_id,))
            row = cursor.fetchone()
            if row:
                from app.schemas.forensic import EmailSession
                session_dict = json.loads(row["session_result_json"])
                session = EmailSession.model_validate(session_dict)

        elif request.analysis_id:
            cursor.execute("SELECT session_result_json FROM sessions WHERE analysis_id = ? LIMIT 1;", (request.analysis_id,))
            row = cursor.fetchone()
            if row:
                from app.schemas.forensic import EmailSession
                session_dict = json.loads(row["session_result_json"])
                session = EmailSession.model_validate(session_dict)

        conn.close()

        if not session:
            # Fallback construct basic session for simulation
            from app.schemas.forensic import (
                EmailSession,
                SessionSecurityAssessment,
                SecurityGrade,
                EmailProtocol,
                SecurityMode,
                SecurityFinding,
                FindingSeverity,
                FindingCategory,
            )

            mock_findings = []
            rem_finding_map = {
                "DISABLE_DEPRECATED_TLS": "FINDING-DEPRECATED-TLS-1-0",
                "REQUIRE_STARTTLS": "FINDING-PLAINTEXT-AUTH",
                "ENABLE_FORWARD_SECRECY": "FINDING-NO-PFS-STATIC-RSA",
                "REPLACE_WEAK_CIPHER": "FINDING-WEAK-CIPHER-3DES",
                "RENEW_CERTIFICATE": "FINDING-CERT-EXPIRED",
                "UPGRADE_RSA_KEY": "FINDING-WEAK-RSA-1024",
                "ENABLE_DMARC_POLICY": "FINDING-DMARC-POLICY-NONE",
                "FIX_DMARC_CONFIGURATION": "FINDING-DMARC-SYNTAX",
                "ENABLE_SPF_POLICY": "FINDING-SPF-POLICY-ABSENT",
                "FIX_SPF_CONFIGURATION": "FINDING-SPF-PERMERROR",
                "ENABLE_MTA_STS": "FINDING-MTA-STS-TESTING",
                "ENABLE_HYBRID_PQC": "FINDING-PQC-CLASSICAL-KEX",
            }
            for r_id in request.remediation_ids:
                if r_id in rem_finding_map:
                    mock_findings.append(
                        SecurityFinding(
                            id=rem_finding_map[r_id],
                            title=f"Mock finding for {r_id}",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.CRYPTOGRAPHIC_STRENGTH,
                            description=f"Simulated finding for {r_id}",
                        )
                    )

            session = EmailSession(
                session_id=request.session_id or request.analysis_id or "sim-session-01",
                stream_index=0,
                protocol=EmailProtocol.SMTP,
                security_mode=SecurityMode.PLAINTEXT,
                client_ip="127.0.0.1",
                client_port=10000,
                server_ip="127.0.0.1",
                server_port=25,
                security_assessment=SessionSecurityAssessment(
                    grade=SecurityGrade.F,
                    findings=mock_findings,
                    post_quantum_ready=False,
                ),
            )

        # Run deterministic simulation
        report = RemediationSimulator.simulate(
            session=session,
            remediations=request.remediation_ids,
            parameters=request.parameters or {},
        )

        obs = report.observed_summary
        sim = report.simulated_summary

        # Build PostureLabel map for each finding
        posture_labels: Dict[str, PostureLabel] = {}
        for f in (report.projected_findings_removed or []):
            fid = f.get("id") or f.get("finding_id") or "unknown"
            posture_labels[fid] = PostureLabel.ASSUMED_AFTER_FIX
        for f in (report.projected_findings_remaining or []):
            fid = f.get("id") or f.get("finding_id") or "unknown"
            posture_labels[fid] = PostureLabel.UNCHANGED

        return SimulateFixResponse(
            session_id=session.session_id,
            observed_grade=obs.security_grade if obs else "F",
            observed_score=obs.score if obs else 0,
            observed_findings_count=obs.findings_count if obs else 0,
            projected_grade=sim.projected_security_grade if sim else "F",
            projected_score=sim.projected_score if sim else 0,
            projected_findings_count=sim.projected_findings_count if sim else 0,
            applied_remediations=report.applied_remediations,
            not_applicable_remediations=list(dict.fromkeys(report.not_applicable_remediations + report.unsupported_remediations)),
            findings_resolved=report.projected_findings_removed,
            findings_remaining=report.projected_findings_remaining,
            posture_labels=posture_labels,
            assumptions=report.assumptions,
            limitations=report.projection_limitations,
        )

    simulate_fix = simulate_fixes

    @classmethod
    def create_plan(
        cls,
        request: RemediationPlanCreateRequest,
        created_by: str = "analyst-01",
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> RemediationPlan:
        """Create a new case/target remediation plan in PROPOSED status."""
        plan_id = f"plan-{uuid.uuid4().hex[:8]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        # Generate guidance items based on requested finding codes or platform
        playbook_resp = cls.generate_playbook(
            PlaybookGenerationRequest(
                analysis_id=request.analysis_id,
                case_id=request.case_id,
                target_id=request.target_id,
                finding_codes=request.finding_codes,
                platform=request.platform,
            ),
            db_path=db_path,
        )

        plan_items: List[RemediationPlanItem] = []
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        # Collect and deduplicate assumptions & limitations
        assumptions: List[str] = []
        limitations: List[str] = []
        for p_item in playbook_resp.items:
            assumptions.extend(p_item.assumptions)
            limitations.extend(p_item.limitations)
        assumptions = list(dict.fromkeys(assumptions))
        limitations = list(dict.fromkeys(limitations))

        # Insert master plan FIRST to satisfy foreign key constraint
        cursor.execute(
            """
            INSERT INTO remediation_plans (
                plan_id, case_id, analysis_id, target_id, title, description,
                platform, status, version, assumptions_json, limitations_json,
                created_by, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PROPOSED', 1, ?, ?, ?, ?, ?);
            """,
            (
                plan_id,
                request.case_id,
                request.analysis_id,
                request.target_id,
                request.title,
                request.description,
                request.platform.value,
                json.dumps(assumptions),
                json.dumps(limitations),
                created_by,
                now_iso,
                now_iso,
            ),
        )

        # Insert plan items
        for p_item in playbook_resp.items:
            item_id = f"item-{uuid.uuid4().hex[:8]}"
            plan_items.append(
                RemediationPlanItem(
                    item_id=item_id,
                    plan_id=plan_id,
                    finding_code=p_item.finding_code,
                    remediation_id=p_item.remediation_id,
                    action_title=p_item.action_title,
                    category=p_item.category,
                    priority=p_item.priority,
                    guidance_text=p_item.guidance_text,
                    config_snippet=p_item.config_snippet,
                    expected_security_effect=p_item.expected_security_effect,
                    validation_steps=p_item.validation_steps,
                    rollback_guidance=p_item.rollback_guidance,
                    status=RemediationStatus.PROPOSED,
                    created_at=now_iso,
                )
            )
            cursor.execute(
                """
                INSERT INTO remediation_plan_items (
                    item_id, plan_id, finding_code, remediation_id, action_title,
                    category, priority, guidance_text, config_snippet, expected_security_effect,
                    validation_steps_json, rollback_guidance, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PROPOSED', ?);
                """,
                (
                    item_id,
                    plan_id,
                    p_item.finding_code,
                    p_item.remediation_id,
                    p_item.action_title,
                    p_item.category.value,
                    p_item.priority.value,
                    p_item.guidance_text,
                    p_item.config_snippet,
                    p_item.expected_security_effect,
                    json.dumps(p_item.validation_steps),
                    p_item.rollback_guidance,
                    now_iso,
                ),
            )

        # Add custom items if provided
        if request.custom_items:
            for c_item in request.custom_items:
                c_item_id = f"item-{uuid.uuid4().hex[:8]}"
                plan_items.append(
                    RemediationPlanItem(
                        item_id=c_item_id,
                        plan_id=plan_id,
                        finding_code=c_item.get("finding_code", "CUSTOM_SECURITY_TASK"),
                        remediation_id=c_item.get("remediation_id", "CUSTOM_REMEDIATION"),
                        action_title=c_item.get("action_title", "Custom Security Hardening Step"),
                        category=RemediationCategory(c_item.get("category", RemediationCategory.MAIL_SERVER_HARDENING.value)),
                        priority=RemediationPriority(c_item.get("priority", RemediationPriority.MEDIUM.value)),
                        guidance_text=c_item.get("guidance_text", "Custom remediation guidance"),
                        config_snippet=c_item.get("config_snippet"),
                        expected_security_effect=c_item.get("expected_security_effect"),
                        validation_steps=c_item.get("validation_steps", []),
                        rollback_guidance=c_item.get("rollback_guidance"),
                        status=RemediationStatus.PROPOSED,
                        created_at=now_iso,
                    )
                )
                cursor.execute(
                    """
                    INSERT INTO remediation_plan_items (
                        item_id, plan_id, finding_code, remediation_id, action_title,
                        category, priority, guidance_text, config_snippet, expected_security_effect,
                        validation_steps_json, rollback_guidance, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PROPOSED', ?);
                    """,
                    (
                        c_item_id,
                        plan_id,
                        c_item.get("finding_code", "CUSTOM_SECURITY_TASK"),
                        c_item.get("remediation_id", "CUSTOM_REMEDIATION"),
                        c_item.get("action_title", "Custom Security Hardening Step"),
                        c_item.get("category", RemediationCategory.MAIL_SERVER_HARDENING.value),
                        c_item.get("priority", RemediationPriority.MEDIUM.value),
                        c_item.get("guidance_text", "Custom remediation guidance"),
                        c_item.get("config_snippet"),
                        c_item.get("expected_security_effect"),
                        json.dumps(c_item.get("validation_steps", [])),
                        c_item.get("rollback_guidance"),
                        now_iso,
                    ),
                )

        conn.commit()
        conn.close()

        ForensicRepository.record_audit_event(
            event_type="REMEDIATION_PLAN_CREATED",
            object_type="REMEDIATION_PLAN",
            object_id=plan_id,
            details=f"Created remediation plan '{request.title}' ({request.platform.value}) with {len(plan_items)} advisory steps.",
            actor=actor,
            db_path=db_path,
        )

        return RemediationPlan(
            plan_id=plan_id,
            case_id=request.case_id,
            analysis_id=request.analysis_id,
            target_id=request.target_id,
            title=request.title,
            description=request.description,
            platform=request.platform,
            status=RemediationStatus.PROPOSED,
            version=1,
            assumptions=assumptions,
            limitations=limitations,
            items=plan_items,
            created_by=created_by,
            created_at=now_iso,
            updated_at=now_iso,
        )

    @classmethod
    def get_plan(cls, plan_id: str, db_path: Optional[str] = None) -> Optional[RemediationPlan]:
        """Retrieve a remediation plan and all its items by ID."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM remediation_plans WHERE plan_id = ?;", (plan_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return None

        rd = dict(row)
        cursor.execute("SELECT * FROM remediation_plan_items WHERE plan_id = ? ORDER BY created_at ASC;", (plan_id,))
        item_rows = cursor.fetchall()
        conn.close()

        items: List[RemediationPlanItem] = []
        for ir in item_rows:
            ird = dict(ir)
            val_steps = []
            if ird.get("validation_steps_json"):
                try:
                    val_steps = json.loads(ird["validation_steps_json"])
                except Exception:
                    val_steps = []
            items.append(
                RemediationPlanItem(
                    item_id=ird["item_id"],
                    plan_id=ird["plan_id"],
                    finding_id=ird.get("finding_id"),
                    finding_code=ird["finding_code"],
                    remediation_id=ird["remediation_id"],
                    action_title=ird["action_title"],
                    category=RemediationCategory(ird["category"]),
                    priority=RemediationPriority(ird["priority"]),
                    guidance_text=ird["guidance_text"],
                    config_snippet=ird.get("config_snippet"),
                    expected_security_effect=ird.get("expected_security_effect"),
                    validation_steps=val_steps,
                    rollback_guidance=ird.get("rollback_guidance"),
                    status=RemediationStatus(ird["status"]),
                    evidence_reference=ird.get("evidence_reference"),
                    created_at=ird["created_at"],
                )
            )

        assumptions = []
        if rd.get("assumptions_json"):
            try:
                assumptions = json.loads(rd["assumptions_json"])
            except Exception:
                assumptions = []

        limitations = []
        if rd.get("limitations_json"):
            try:
                limitations = json.loads(rd["limitations_json"])
            except Exception:
                limitations = []

        return RemediationPlan(
            plan_id=rd["plan_id"],
            case_id=rd.get("case_id"),
            analysis_id=rd.get("analysis_id"),
            target_id=rd.get("target_id"),
            title=rd["title"],
            description=rd.get("description"),
            platform=RemediationPlatform(rd.get("platform", RemediationPlatform.GENERIC.value)),
            status=RemediationStatus(rd.get("status", RemediationStatus.PROPOSED.value)),
            version=rd.get("version", 1),
            supersedes_plan_id=rd.get("supersedes_plan_id"),
            assumptions=assumptions,
            limitations=limitations,
            items=items,
            created_by=rd.get("created_by", "analyst-01"),
            created_at=rd["created_at"],
            updated_at=rd["updated_at"],
            applied_by=rd.get("applied_by"),
            applied_at=rd.get("applied_at"),
            verified_by=rd.get("verified_by"),
            verified_at=rd.get("verified_at"),
        )

    @classmethod
    def list_plans(
        cls,
        case_id: Optional[str] = None,
        analysis_id: Optional[str] = None,
        target_id: Optional[str] = None,
        status: Optional[RemediationStatus] = None,
        db_path: Optional[str] = None,
    ) -> List[RemediationPlan]:
        """List all remediation plans matching search filters."""
        query = "SELECT plan_id FROM remediation_plans WHERE 1=1"
        params = []
        if case_id:
            query += " AND case_id = ?"
            params.append(case_id)
        if analysis_id:
            query += " AND analysis_id = ?"
            params.append(analysis_id)
        if target_id:
            query += " AND target_id = ?"
            params.append(target_id)
        if status:
            query += " AND status = ?"
            params.append(status.value)
        query += " ORDER BY created_at DESC;"

        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        conn.close()

        results: List[RemediationPlan] = []
        for r in rows:
            plan = cls.get_plan(r["plan_id"], db_path=db_path)
            if plan:
                results.append(plan)
        return results

    @classmethod
    def update_plan(
        cls,
        plan_id: str,
        request: RemediationPlanUpdateRequest,
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> RemediationPlan:
        """Update a remediation plan metadata and bump version if needed."""
        plan = cls.get_plan(plan_id, db_path=db_path)
        if not plan:
            raise ValueError(f"Remediation plan '{plan_id}' not found")

        now_iso = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        title = request.title if request.title is not None else plan.title
        description = request.description if request.description is not None else plan.description
        platform = request.platform.value if request.platform is not None else plan.platform.value
        status = request.status.value if request.status is not None else plan.status.value

        cursor.execute(
            """
            UPDATE remediation_plans
            SET title = ?, description = ?, platform = ?, status = ?, updated_at = ?
            WHERE plan_id = ?;
            """,
            (title, description, platform, status, now_iso, plan_id),
        )
        conn.commit()
        conn.close()

        ForensicRepository.record_audit_event(
            event_type="REMEDIATION_PLAN_UPDATED",
            object_type="REMEDIATION_PLAN",
            object_id=plan_id,
            details=f"Updated plan '{plan_id}' details. Status: {status}",
            actor=actor,
            db_path=db_path,
        )

        return cls.get_plan(plan_id, db_path=db_path)

    @classmethod
    def mark_applied(
        cls,
        plan_id: str,
        request: MarkAppliedRequest,
        applied_by: str = "analyst-01",
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> RemediationPlan:
        """Mark remediation plan and its items as USER_REPORTED_APPLIED."""
        plan = cls.get_plan(plan_id, db_path=db_path)
        if not plan:
            raise ValueError(f"Remediation plan '{plan_id}' not found")

        now_iso = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        # Update specific items or all items
        if request.item_ids:
            for item_id in request.item_ids:
                cursor.execute(
                    "UPDATE remediation_plan_items SET status = 'USER_REPORTED_APPLIED' WHERE item_id = ? AND plan_id = ?;",
                    (item_id, plan_id),
                )
        else:
            cursor.execute(
                "UPDATE remediation_plan_items SET status = 'USER_REPORTED_APPLIED' WHERE plan_id = ?;",
                (plan_id,),
            )

        cursor.execute(
            """
            UPDATE remediation_plans
            SET status = 'USER_REPORTED_APPLIED', applied_by = ?, applied_at = ?, updated_at = ?
            WHERE plan_id = ?;
            """,
            (applied_by, now_iso, now_iso, plan_id),
        )
        conn.commit()
        conn.close()

        ForensicRepository.record_audit_event(
            event_type="REMEDIATION_APPLIED",
            object_type="REMEDIATION_PLAN",
            object_id=plan_id,
            details=f"Remediation plan '{plan_id}' marked as applied by {applied_by}. Notes: {request.notes or 'None'}",
            actor=actor,
            db_path=db_path,
        )

        return cls.get_plan(plan_id, db_path=db_path)

    @classmethod
    def verify_plan(
        cls,
        plan_id: str,
        request: VerificationRequest,
        verified_by: str = "analyst-01",
        actor: Optional[ActorContext] = None,
        db_path: Optional[str] = None,
    ) -> VerificationRecord:
        """
        Runs an evidence-based verification comparing prior plan items against newly observed
        forensic evidence (active scan or PCAP analysis).
        """
        plan = cls.get_plan(plan_id, db_path=db_path)
        if not plan:
            raise ValueError(f"Remediation plan '{plan_id}' not found")

        conn = get_db_connection(db_path)
        cursor = conn.cursor()

        # Gather new findings from new_analysis_id or new_scan_id
        new_finding_codes: Set[str] = set()
        evidence_ref = ""

        if request.new_analysis_id:
            evidence_ref = f"analysis:{request.new_analysis_id}"
            cursor.execute("SELECT finding_id, rule_id FROM findings WHERE analysis_id = ?;", (request.new_analysis_id,))
            rows = cursor.fetchall()
            for r in rows:
                if r["finding_id"]:
                    new_finding_codes.add(r["finding_id"].upper())
                if r["rule_id"]:
                    new_finding_codes.add(r["rule_id"].upper())

        elif request.new_scan_id:
            evidence_ref = f"scan:{request.new_scan_id}"
            cursor.execute("SELECT result_json FROM active_scans WHERE scan_id = ?;", (request.new_scan_id,))
            row = cursor.fetchone()
            if row and row["result_json"]:
                try:
                    res = json.loads(row["result_json"])
                    for p_res in res.get("port_results", []):
                        for f in p_res.get("findings", []):
                            fid = f.get("id") or f.get("finding_id") or ""
                            if fid:
                                new_finding_codes.add(fid.upper())
                except Exception:
                    pass

        # Evaluate resolution of each plan item
        prior_finding_count = len(plan.items)
        resolved_count = 0
        remaining_count = 0
        details: Dict[str, Any] = {"resolved_items": [], "unresolved_items": []}

        for item in plan.items:
            fc = item.finding_code.upper()
            # If finding code is no longer present in new findings, it's resolved
            is_still_present = (fc in new_finding_codes or any(fc in nfc for nfc in new_finding_codes))
            if not is_still_present and evidence_ref:
                resolved_count += 1
                details["resolved_items"].append({"item_id": item.item_id, "finding_code": item.finding_code})
                cursor.execute(
                    "UPDATE remediation_plan_items SET status = 'VERIFIED', evidence_reference = ? WHERE item_id = ?;",
                    (evidence_ref, item.item_id),
                )
            else:
                remaining_count += 1
                details["unresolved_items"].append({"item_id": item.item_id, "finding_code": item.finding_code})
                cursor.execute(
                    "UPDATE remediation_plan_items SET status = 'FAILED_VERIFICATION', evidence_reference = ? WHERE item_id = ?;",
                    (evidence_ref, item.item_id),
                )

        verification_status = VerificationStatus.VERIFIED if (remaining_count == 0 and resolved_count > 0) else VerificationStatus.FAILED
        plan_status = RemediationStatus.VERIFIED if verification_status == VerificationStatus.VERIFIED else RemediationStatus.FAILED_VERIFICATION

        verification_id = f"verif-{uuid.uuid4().hex[:8]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        cursor.execute(
            """
            INSERT INTO remediation_verifications (
                verification_id, plan_id, verified_by, verified_at, verification_status,
                verification_method, verification_evidence_reference, prior_finding_count,
                resolved_finding_count, remaining_finding_count, notes, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                verification_id,
                plan_id,
                verified_by,
                now_iso,
                verification_status.value,
                request.verification_method.value,
                evidence_ref,
                prior_finding_count,
                resolved_count,
                remaining_count,
                request.notes,
                json.dumps(details),
            ),
        )

        cursor.execute(
            """
            UPDATE remediation_plans
            SET status = ?, verified_by = ?, verified_at = ?, updated_at = ?
            WHERE plan_id = ?;
            """,
            (plan_status.value, verified_by, now_iso, now_iso, plan_id),
        )

        conn.commit()
        conn.close()

        ForensicRepository.record_audit_event(
            event_type="REMEDIATION_VERIFIED" if verification_status == VerificationStatus.VERIFIED else "REMEDIATION_VERIFICATION_FAILED",
            object_type="REMEDIATION_PLAN",
            object_id=plan_id,
            details=f"Verification status: {verification_status.value} (Resolved: {resolved_count}, Remaining: {remaining_count}) backed by evidence '{evidence_ref}'.",
            actor=actor,
            db_path=db_path,
        )

        return VerificationRecord(
            verification_id=verification_id,
            plan_id=plan_id,
            verified_by=verified_by,
            verified_at=now_iso,
            verification_status=verification_status,
            verification_method=request.verification_method,
            verification_evidence_reference=evidence_ref,
            prior_finding_count=prior_finding_count,
            resolved_finding_count=resolved_count,
            remaining_finding_count=remaining_count,
            notes=request.notes,
            details=details,
        )

    @classmethod
    def list_verifications(cls, plan_id: str, db_path: Optional[str] = None) -> List[VerificationRecord]:
        """List all verification audit records for a remediation plan."""
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM remediation_verifications WHERE plan_id = ? ORDER BY verified_at DESC;", (plan_id,))
        rows = cursor.fetchall()
        conn.close()

        results: List[VerificationRecord] = []
        for r in rows:
            rd = dict(r)
            details = {}
            if rd.get("details_json"):
                try:
                    details = json.loads(rd["details_json"])
                except Exception:
                    details = {}
            results.append(
                VerificationRecord(
                    verification_id=rd["verification_id"],
                    plan_id=rd["plan_id"],
                    verified_by=rd["verified_by"],
                    verified_at=rd["verified_at"],
                    verification_status=VerificationStatus(rd["verification_status"]),
                    verification_method=VerificationMethod(rd["verification_method"]),
                    verification_evidence_reference=rd.get("verification_evidence_reference"),
                    prior_finding_count=rd["prior_finding_count"],
                    resolved_finding_count=rd["resolved_finding_count"],
                    remaining_finding_count=rd["remaining_finding_count"],
                    notes=rd.get("notes"),
                    details=details,
                )
            )
        return results
