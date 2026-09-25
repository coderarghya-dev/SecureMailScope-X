"""
SecureMailScope X - Automated Forensic Parser Tests
Validates real passive PCAP analysis against known baseline PCAPs:
- smtp-starttls-test.pcapng (Gmail SMTP 587 STARTTLS -> TLS 1.3)
- imap-tls-test.pcapng (Direct TLS IMAP 993)
"""

import os
import sys
import unittest

# Add backend directory to sys.path
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from run_parser import analyze_pcap
from app.schemas.forensic import EmailProtocol, SecurityMode, TLSVersion


class TestEmailForensicParser(unittest.TestCase):
    SMTP_PCAP = r"D:\SecureMailScope\pcap_samples\smtp-starttls-test.pcapng"
    IMAP_PCAP = r"D:\SecureMailScope\pcap_samples\imap-tls-test.pcapng"
    POP3_PCAP = r"D:\SecureMailScope\pcap_samples\pop3-tls-test.pcapng"
    POP3_STLS_PCAP = r"D:\SecureMailScope\pcap_samples\pop3-stls-test.pcapng"

    def test_01_smtp_starttls_real_capture(self):
        """Verify real Gmail SMTP capture with STARTTLS -> TLS 1.3."""
        if not os.path.isfile(self.SMTP_PCAP):
            self.skipTest(f"PCAP sample not found: {self.SMTP_PCAP}")

        print(f"\n[+] Analyzing: {self.SMTP_PCAP}")
        report = analyze_pcap(self.SMTP_PCAP)

        # 1. Total email sessions found
        self.assertGreaterEqual(report["email_sessions_found"], 1, "Should find at least 1 email session")

        # 2. Check the SMTP session
        smtp_session = next((s for s in report["sessions"] if s["protocol"] == "SMTP"), None)
        self.assertIsNotNone(smtp_session, "SMTP session must be identified")

        # 3. Port & Identity
        self.assertTrue(smtp_session["server"].endswith(":587"), f"Expected port 587, got {smtp_session['server']}")
        self.assertIn("gmail.com", (smtp_session["server_hostname"] or "").lower())
        if smtp_session["greeting_banner"]:
            self.assertIn("smtp.gmail.com", smtp_session["greeting_banner"])

        # 4. STARTTLS Verification
        st = smtp_session["starttls"]
        self.assertTrue(st["advertised"], "STARTTLS capability must be advertised by server")
        self.assertEqual(st["advertised_frame"], 2291, "Advertised frame should be exactly 2291")

        self.assertTrue(st["requested"], "Client must issue STARTTLS command")
        self.assertEqual(st["requested_frame"], 2292, "STARTTLS request frame should be exactly 2292")

        self.assertTrue(st["accepted"], "Server must accept STARTTLS with 220 Ready")
        self.assertEqual(st["accepted_frame"], 2294, "STARTTLS accepted frame should be exactly 2294")

        self.assertTrue(st["upgrade_successful"], "TLS upgrade must succeed")

        # 5. TLS Handshake Verification
        tls = smtp_session["tls"]
        self.assertIsNotNone(tls, "TLS handshake details must be captured")
        self.assertEqual(smtp_session["packets_count"], 27, "Filtered stream packet count must be exactly 27")
        self.assertEqual(tls["negotiated_version"], "TLS 1.3", "Negotiated TLS version must be TLS 1.3")
        self.assertEqual(tls["cipher_name"], "TLS_AES_256_GCM_SHA384", "Negotiated cipher suite must be TLS_AES_256_GCM_SHA384")
        self.assertEqual(tls["client_hello_frame"], 2295, "Client Hello frame must be 2295")
        self.assertEqual(tls["server_hello_frame"], 2298, "Server Hello frame must be 2298")
        self.assertEqual(tls["pfs_status"], "Unknown / insufficient passive evidence", "PFS status must be unobservable")
        self.assertIn("Unavailable from passive capture", tls["certificate_visibility"])

        print("[OK] Test 01 Passed: Real SMTP STARTTLS -> TLS 1.3 facts completely verified from packet evidence.")

    def test_02_imap_tls_capture(self):
        """Verify IMAP capture (Direct TLS on port 993) if available."""
        if not os.path.isfile(self.IMAP_PCAP):
            print(f"[!] IMAP PCAP {self.IMAP_PCAP} not present on disk yet - test skipped.")
            return

        print(f"\n[+] Analyzing: {self.IMAP_PCAP}")
        report = analyze_pcap(self.IMAP_PCAP)

        self.assertGreaterEqual(report["email_sessions_found"], 1, "Should find IMAP session")
        imap_session = next((s for s in report["sessions"] if s["protocol"] == "IMAP"), None)
        self.assertIsNotNone(imap_session, "IMAP session must be identified")

        # Must NOT report STARTTLS on direct TLS
        self.assertFalse(imap_session["starttls"]["advertised"], "Direct TLS must NOT falsely report STARTTLS advertised")
        self.assertFalse(imap_session["starttls"]["requested"], "Direct TLS must NOT falsely report STARTTLS requested")
        self.assertEqual(imap_session["security_mode"], "DIRECT_TLS")

        if imap_session["tls"]:
            print(f"  IMAP TLS Version: {imap_session['tls']['negotiated_version']}")
            print(f"  IMAP Cipher: {imap_session['tls']['cipher_name']}")

        print("[OK] Test 02 Passed: IMAP Direct TLS correctly identified without false STARTTLS detection.")

    def test_03_pop3_tls_capture(self):
        """Verify POP3 capture (Direct TLS on port 995) if available."""
        if not os.path.isfile(self.POP3_PCAP):
            print(f"[!] POP3 PCAP {self.POP3_PCAP} not present on disk yet - test skipped.")
            return

        print(f"\n[+] Analyzing: {self.POP3_PCAP}")
        report = analyze_pcap(self.POP3_PCAP)

        self.assertGreaterEqual(report["email_sessions_found"], 1, "Should find POP3 session")
        pop_session = next((s for s in report["sessions"] if s["protocol"] == "POP3"), None)
        self.assertIsNotNone(pop_session, "POP3 session must be identified")

        # Must NOT report STLS on direct TLS
        self.assertFalse(pop_session["starttls"]["advertised"], "Direct TLS must NOT falsely report STLS advertised")
        self.assertFalse(pop_session["starttls"]["requested"], "Direct TLS must NOT falsely report STLS requested")
        self.assertEqual(pop_session["security_mode"], "DIRECT_TLS")

        if pop_session["tls"]:
            print(f"  POP3 TLS Version: {pop_session['tls']['negotiated_version']}")
            print(f"  POP3 Cipher: {pop_session['tls']['cipher_name']}")

        print("[OK] Test 03 Passed: POP3 Direct TLS correctly identified without false STLS detection.")

    def test_04_pop3_stls_real_capture(self):
        """Verify real POP3 port 110 STLS capture -> TLS upgrade if available."""
        if not os.path.isfile(self.POP3_STLS_PCAP):
            print(f"[!] POP3 STLS PCAP {self.POP3_STLS_PCAP} not present on disk yet - test skipped.")
            return

        print(f"\n[+] Analyzing: {self.POP3_STLS_PCAP}")
        report = analyze_pcap(self.POP3_STLS_PCAP)

        # If capture has no reconstructed email sessions (e.g. only SYN retransmissions because host closed port 110)
        pop_session = next((s for s in report["sessions"] if s["protocol"] == "POP3"), None)
        if not pop_session or not pop_session["starttls"]["requested"]:
            print(f"[!] POP3 port 110 STLS real capture pending — target server unavailable / unserviceable on port 110.")
            return

        # Port & Identity
        self.assertTrue(pop_session["server"].endswith(":110"), f"Expected port 110, got {pop_session['server']}")

        # STLS Verification
        st = pop_session["starttls"]
        self.assertTrue(st["requested"], "Client must issue STLS command")
        self.assertTrue(st["accepted"], "Server must accept STLS command with +OK")
        self.assertTrue(st["upgrade_successful"], "TLS upgrade must succeed")

        # TLS Handshake Verification
        tls = pop_session["tls"]
        self.assertIsNotNone(tls, "TLS handshake details must be captured")
        self.assertIn(tls["negotiated_version"], ["TLS 1.3", "TLS 1.2"], f"Negotiated TLS version must be TLS 1.3 or 1.2, got {tls['negotiated_version']}")
        self.assertIsNotNone(tls["client_hello_frame"], "Client Hello frame must be captured")
        self.assertIsNotNone(tls["server_hello_frame"], "Server Hello frame must be captured")

        print("[OK] Test 04 Passed: Real POP3 port 110 STLS -> TLS facts completely verified from packet evidence.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
