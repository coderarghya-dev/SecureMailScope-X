import os
import sys

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BACKEND_DIR, "..", "backend"))

from app.core.tshark_detector import TSharkDetector
import subprocess

pcap = r"D:\SecureMailScope\pcap_samples\smtp-tls12-cert.pcapng"
tshark = TSharkDetector.find_tshark()
print("Found TShark:", tshark)

if tshark:
    cmd = [
        tshark, "-r", pcap,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "tls.handshake.type",
        "-e", "tls.handshake.certificate",
        "-e", "_ws.col.Info"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    print("TShark Output:\n", res.stdout)
