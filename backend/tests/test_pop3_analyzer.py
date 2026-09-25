"""
SecureMailScope X - POP3 / POP3S Protocol Analyzer Unit Tests
Deterministic offline unit test suite validating POP3 RFC 1939, RFC 2449, RFC 2595 STLS state machine logic.
"""

import os
import sys
import unittest

# Ensure backend root is in sys.path
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.protocols.pop3_analyzer import POP3Analyzer
from app.schemas.forensic import PacketEvidence, STARTTLSState


def make_packet(frame_number: int, summary: str, payload: str = None) -> PacketEvidence:
    """Helper to construct realistic directional PacketEvidence fixture."""
    clean = summary.strip()
    is_server = (
        clean.startswith("S:") or 
        clean.startswith("+OK") or 
        clean.startswith("-ERR") or 
        clean.startswith("Response:") or
        "Server Hello" in clean
    )
    src_port = 110 if is_server else 50000
    dst_port = 50000 if is_server else 110

    return PacketEvidence(
        frame_number=frame_number,
        timestamp_epoch=1700000000.0 + frame_number,
        timestamp_iso="2026-09-23T20:00:00Z",
        src_ip="192.168.1.1" if is_server else "192.168.1.100",
        src_port=src_port,
        dst_ip="192.168.1.100" if is_server else "192.168.1.1",
        dst_port=dst_port,
        protocol="POP",
        length=100,
        summary=summary,
        raw_payload_preview=payload or summary
    )


class TestPOP3Analyzer(unittest.TestCase):
    def test_01_direct_tls_no_false_stls(self):
        """Port 995 POP3S Direct TLS must never falsely report STLS."""
        packets = [
            make_packet(1, "Client Hello"),
            make_packet(2, "Server Hello"),
            make_packet(3, "+OK POP3 server ready")
        ]
        state, banner = POP3Analyzer.analyze_stream_packets(packets, is_direct_tls=True)
        self.assertFalse(state.advertised, "Direct TLS must not report STLS advertised")
        self.assertFalse(state.requested, "Direct TLS must not report STLS requested")
        self.assertFalse(state.accepted, "Direct TLS must not report STLS accepted")
        self.assertFalse(state.failed, "Direct TLS must not report STLS failed")
        self.assertIsNone(banner, "Direct TLS must not expose plaintext banner")

    def test_02_stls_full_negotiation(self):
        """Port 110: Banner -> CAPA with STLS -> STLS command -> +OK Begin TLS."""
        packets = [
            make_packet(10, "S: +OK POP3 server ready <xyz@mail.example.com>"),
            make_packet(11, "C: CAPA"),
            make_packet(12, "S: +OK Capability list follows\r\nUSER\r\nSTLS\r\nTOP\r\n."),
            make_packet(13, "C: STLS"),
            make_packet(14, "S: +OK Begin TLS negotiation")
        ]
        state, banner = POP3Analyzer.analyze_stream_packets(packets, is_direct_tls=False)
        self.assertIsNotNone(banner, "Server banner must be extracted")
        self.assertIn("POP3 server ready", banner)
        
        # Frame 12: Server advertises STLS in CAPA response
        self.assertTrue(state.advertised, "STLS must be detected as advertised in CAPA response")
        self.assertEqual(state.advertised_frame, 12, "STLS advertisement must be from Frame 12")
        
        # Frame 13: Client sends STLS command
        self.assertTrue(state.requested, "Client STLS command must be detected")
        self.assertEqual(state.requested_frame, 13, "STLS command request must be from Frame 13")
        self.assertEqual(state.requested_command, "STLS")
        
        # Frame 14: Server accepts STLS command with +OK
        self.assertTrue(state.accepted, "Server +OK acceptance must be detected")
        self.assertEqual(state.accepted_frame, 14, "STLS acceptance must be from Frame 14")
        self.assertFalse(state.failed, "Successful negotiation must not be marked failed")

    def test_03_stls_rejected(self):
        """Port 110: Client STLS command rejected with -ERR."""
        packets = [
            make_packet(20, "S: +OK POP3 ready"),
            make_packet(21, "C: STLS"),
            make_packet(22, "S: -ERR Command not recognized")
        ]
        state, banner = POP3Analyzer.analyze_stream_packets(packets, is_direct_tls=False)
        self.assertTrue(state.requested, "Client STLS command must be detected")
        self.assertEqual(state.requested_frame, 21, "STLS request must be Frame 21")
        self.assertFalse(state.accepted, "Rejected STLS must not be marked accepted")
        self.assertTrue(state.failed, "Rejected STLS must be marked failed")
        self.assertEqual(state.failure_frame, 22, "Failure response must be Frame 22")
        self.assertIn("Command not recognized", state.failure_reason)

    def test_04_cleartext_only_session(self):
        """Port 110: Plaintext POP3 session without STLS."""
        packets = [
            make_packet(30, "S: +OK POP3 ready"),
            make_packet(31, "C: USER testuser"),
            make_packet(32, "S: +OK Password required"),
            make_packet(33, "C: PASS secret"),
            make_packet(34, "S: +OK Logged in")
        ]
        state, banner = POP3Analyzer.analyze_stream_packets(packets, is_direct_tls=False)
        self.assertIsNotNone(banner)
        self.assertFalse(state.advertised)
        self.assertFalse(state.requested)
        self.assertFalse(state.accepted)
        self.assertFalse(state.failed)

    def test_05_stls_advertised_but_never_requested(self):
        """Port 110: CAPA advertises STLS, but client logs in in cleartext without requesting STLS."""
        packets = [
            make_packet(40, "S: +OK POP3 ready"),
            make_packet(41, "C: CAPA"),
            make_packet(42, "S: +OK Capability list follows\r\nSTLS\r\nUSER\r\n."),
            make_packet(43, "C: USER testuser"),
            make_packet(44, "S: +OK Password required"),
            make_packet(45, "C: PASS secret"),
            make_packet(46, "S: +OK Logged in")
        ]
        state, banner = POP3Analyzer.analyze_stream_packets(packets, is_direct_tls=False)
        self.assertTrue(state.advertised, "STLS advertisement must be detected")
        self.assertEqual(state.advertised_frame, 42)
        self.assertFalse(state.requested, "STLS must not be marked requested")
        self.assertFalse(state.accepted, "STLS must not be marked accepted")
        self.assertFalse(state.failed, "STLS must not be marked failed")

    def test_06_ambiguous_direction_handling(self):
        """Ambiguous packets (non-standard ephemeral ports, no C:/S: prefix) must not match both roles."""
        ambiguous_pkt = PacketEvidence(
            frame_number=50,
            timestamp_epoch=1700000050.0,
            timestamp_iso="2026-09-23T20:00:50Z",
            src_ip="10.0.0.1",
            src_port=40001,
            dst_ip="10.0.0.2",
            dst_port=40002,
            protocol="POP",
            length=80,
            summary="STLS",
            raw_payload_preview="STLS"
        )
        state, _ = POP3Analyzer.analyze_stream_packets([ambiguous_pkt], is_direct_tls=False)
        self.assertTrue(state.requested, "Client command STLS detected from command match")
        self.assertFalse(state.advertised, "Single STLS command must not simultaneously be flagged as server advertisement")


if __name__ == "__main__":
    unittest.main(verbosity=2)
