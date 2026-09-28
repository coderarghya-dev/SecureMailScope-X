import os
import sys

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BACKEND_DIR, "..", "backend"))

from app.protocols.smtp_analyzer import SMTPAnalyzer
import subprocess

pcap = r"D:\SecureMailScope\pcap_samples\smtp-tls12-cert.pcapng"

# Let's run tshark to see what certificate fields are in this pcap
tshark_cmd = [
    "tshark", "-r", pcap,
    "-T", "fields",
    "-e", "frame.number",
    "-e", "ip.src",
    "-e", "tcp.srcport",
    "-e", "tls.record.content_type",
    "-e", "tls.handshake.type",
    "-e", "tls.handshake.certificate",
    "-e", "x509sat.printableString",
    "-e", "x509sat.uTF8String",
    "-e", "x509ce.dNSName",
    "-e", "x509af.notBefore",
    "-e", "x509af.notAfter"
]

try:
    res = subprocess.run(tshark_cmd, capture_output=True, text=True)
    print("TShark output:")
    print(res.stdout[:2000])
except Exception as e:
    print("TShark execution error:", e)
