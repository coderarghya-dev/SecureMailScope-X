import os
import sys
import unittest

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.dns.email_auth_analyzer import EmailAuthAnalyzer


class TestEmailAuthAnalyzer(unittest.TestCase):

    def test_01_robust_spf_and_dmarc(self):
        txt = ["v=spf1 include:_spf.google.com -all"]
        dmarc = "v=DMARC1; p=reject; pct=100"
        mta_sts = "v=STSv1; mode=enforce"

        res = EmailAuthAnalyzer.analyze_records(
            domain="example.com",
            txt_records=txt,
            dmarc_txt=dmarc,
            mta_sts_txt=mta_sts,
            is_active=False,
            data_source="Offline Test Mock",
        )

        self.assertEqual(res.overall_auth_posture, "ROBUST")
        self.assertEqual(res.spf_policy, "PASS_RESTRICTIVE (-all)")
        self.assertEqual(res.dmarc_policy, "reject")
        self.assertEqual(res.mta_sts_mode, "ENFORCE")
        self.assertEqual(len(res.findings), 0)

    def test_02_weak_dmarc_none_and_insecure_spf(self):
        txt = ["v=spf1 +all"]
        dmarc = "v=DMARC1; p=none"

        res = EmailAuthAnalyzer.analyze_records(
            domain="vulnerable.org",
            txt_records=txt,
            dmarc_txt=dmarc,
            is_active=False,
        )

        self.assertEqual(res.spf_policy, "INSECURE (+all)")
        self.assertEqual(res.dmarc_policy, "none")
        self.assertTrue(any(f["id"] == "FINDING-SPF-ALLOW-ALL" for f in res.findings))
        self.assertTrue(any(f["id"] == "FINDING-DMARC-POLICY-NONE" for f in res.findings))

    def test_03_missing_records(self):
        res = EmailAuthAnalyzer.analyze_records(
            domain="missing.com",
            txt_records=[],
            dmarc_txt=None,
            is_active=False,
        )

        self.assertEqual(res.spf_policy, "MISSING")
        self.assertEqual(res.dmarc_policy, "MISSING")
        self.assertEqual(res.overall_auth_posture, "DEFICIENT")
        self.assertTrue(any(f["id"] == "FINDING-SPF-MISSING" for f in res.findings))
        self.assertTrue(any(f["id"] == "FINDING-DMARC-MISSING" for f in res.findings))


if __name__ == "__main__":
    unittest.main()
