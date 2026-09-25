import os
import sys
import unittest

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.schemas.forensic import (
    EmailSession, EmailProtocol, SecurityMode, SessionSecurityAssessment,
    SecurityGrade, SecurityFinding, FindingSeverity, FindingCategory, TLSVersion
)
from app.scanner.active_scanner import ActiveMailScanner, PORT_SERVICE_MAP
from app.simulation.simulate_fix import SimulateFixEngine


class TestScannerAndSimulation(unittest.TestCase):

    def test_01_scanner_port_mapping(self):
        self.assertEqual(PORT_SERVICE_MAP[25], ("SMTP", "STARTTLS"))
        self.assertEqual(PORT_SERVICE_MAP[993], ("IMAP", "DIRECT_TLS"))
        self.assertEqual(PORT_SERVICE_MAP[110], ("POP3", "STLS"))

    def test_02_simulate_fix_removes_static_rsa(self):
        session = EmailSession(
            session_id="stream_0_test",
            stream_index=0,
            protocol=EmailProtocol.SMTP,
            security_mode=SecurityMode.STARTTLS_ACCEPTED,
            client_ip="127.0.0.1",
            client_port=1000,
            server_ip="127.0.0.1",
            server_port=25,
            security_assessment=SessionSecurityAssessment(
                grade=SecurityGrade.C,
                findings=[
                    SecurityFinding(
                        id="FINDING-NO-FORWARD-SECRECY",
                        title="No Forward Secrecy",
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.FORWARD_SECRECY,
                        description="Static RSA key exchange",
                    )
                ]
            )
        )

        projected = SimulateFixEngine.simulate(
            session,
            remove_static_rsa=True,
            require_tls13=True,
            enable_pqc_hybrid=True,
        )

        self.assertEqual(projected.current_grade, "C")
        self.assertEqual(projected.projected_grade, "A+")
        self.assertEqual(projected.projected_findings_count, 0)
        self.assertEqual(len(projected.eliminated_findings), 1)
        self.assertIn("PROJECTED POSTURE", projected.disclaimer)


if __name__ == "__main__":
    unittest.main()
