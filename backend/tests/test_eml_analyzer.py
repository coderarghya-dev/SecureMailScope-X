import os
import sys
import unittest

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.eml.eml_analyzer import EMLForensicAnalyzer


SAMPLE_EML = """From: Security Alert <alerts@securebank.com>
To: user@example.com
Subject: Notice of Account Activity
Date: Mon, 25 Sep 2026 10:00:00 +0000
Message-ID: <12345678@securebank.com>
Return-Path: <bounce@spoofed-domain.net>
Authentication-Results: mx.example.com;
 spf=pass smtp.mailfrom=bounce@spoofed-domain.net;
 dkim=pass header.i=@securebank.com;
 dmarc=fail (p=reject) header.from=securebank.com
Received: from mail-relay.securebank.com (mail-relay.securebank.com [198.51.100.10])
 by mx.example.com with ESMTPS (TLS1.3/TLS_AES_256_GCM_SHA384)
 for <user@example.com>; Mon, 25 Sep 2026 10:00:02 +0000
Received: from internal-app.securebank.local (internal-app [10.0.0.5])
 by mail-relay.securebank.com with SMTP; Mon, 25 Sep 2026 10:00:01 +0000

This is the body of the email.
"""


class TestEMLAnalyzer(unittest.TestCase):

    def test_01_parse_eml_hops_and_auth(self):
        report = EMLForensicAnalyzer.parse_eml_content(SAMPLE_EML)
        self.assertEqual(report.subject, "Notice of Account Activity")
        self.assertEqual(report.message_id, "<12345678@securebank.com>")
        self.assertEqual(report.total_hops, 2)
        
        # Original header appearance order:
        # Hop 1 (top Received header) is ESMTPS (TLS encrypted)
        # Hop 2 (bottom Received header) is internal SMTP (unencrypted)
        self.assertEqual(report.hops[0].with_protocol, "ESMTPS")
        self.assertTrue(report.hops[0].is_tls_encrypted)
        self.assertEqual(report.hops[1].with_protocol, "SMTP")
        self.assertFalse(report.hops[1].is_tls_encrypted)

        self.assertTrue(report.has_insecure_hop)
        self.assertEqual(report.dmarc_auth_result, "fail")
        self.assertTrue(any(f["id"] == "FINDING-EML-PLAINTEXT-RELAY-HOP" for f in report.findings))
        self.assertTrue(any(f["id"] == "FINDING-EML-HEADER-FROM-RETURN-PATH-DIFFER" for f in report.findings))


if __name__ == "__main__":
    unittest.main()
