import os
import sys

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BACKEND_DIR, "..", "backend"))

from app.services.analysis_service import AnalysisService

pcap = r"D:\SecureMailScope\pcap_samples\smtp-tls12-cert.pcapng"
report, sessions = AnalysisService._run_pipeline(pcap, "smtp-tls12-cert.pcapng", os.path.getsize(pcap), "test_analysis_cert")

print("Report Sessions:", len(report.sessions))
s = report.sessions[0]
print("Session Protocol:", s.protocol)
print("Session Mode:", s.security_mode)
print("Session TLS Version:", s.tls.negotiated_version)
print("Session TLS Cipher:", s.tls.cipher_name)
print("Session Top-Level cert details:", s.certificate_details)
if s.tls:
    print("TLS Cert Details:", s.tls.certificate_details)
    print("TLS Cert Visibility:", s.tls.certificate_visibility)
