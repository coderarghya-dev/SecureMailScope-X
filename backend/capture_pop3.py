"""
SecureMailScope X - POP3S Direct-TLS Live Capture Utility
Captures authentic POP3 port 995 network traffic to generate D:\\SecureMailScope\\pcap_samples\\pop3-tls-test.pcapng.
Zero fake data: captures real TCP handshake, TLS 1.3 ClientHello/ServerHello, and encrypted POP3 traffic.
"""

import os
import sys
import time
import ssl
import poplib
import socket
import subprocess

# Ensure backend root is in sys.path
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.core.tshark_detector import TSharkDetector
from app.forensic.pcap_reader import PCAPReader
from app.forensic.session_reconstructor import SessionReconstructor


OUTPUT_PCAP = r"D:\SecureMailScope\pcap_samples\pop3-tls-test.pcapng"
TARGET_HOST = "pop.gmail.com"
TARGET_PORT = 995


def find_dumpcap_binary() -> str:
    """Find dumpcap.exe or tshark.exe binary."""
    tshark_path = TSharkDetector.find_tshark()
    if not tshark_path:
        raise RuntimeError("TShark/Wireshark not found on system. Please install Wireshark.")
    
    wireshark_dir = os.path.dirname(tshark_path)
    dumpcap_path = os.path.join(wireshark_dir, "dumpcap.exe")
    if os.path.isfile(dumpcap_path):
        return dumpcap_path
    
    return tshark_path


def capture_real_pop3_session():
    """Execute live packet capture while performing real POP3S TLS handshake."""
    print("=" * 70)
    print(" SECUREMAILSCOPE X — POP3S DIRECT-TLS REAL CAPTURE GENERATOR")
    print("=" * 70)
    
    out_dir = os.path.dirname(OUTPUT_PCAP)
    os.makedirs(out_dir, exist_ok=True)
    
    capture_bin = find_dumpcap_binary()
    print(f"[+] Capture Engine: {capture_bin}")
    print(f"[+] Output Target:  {OUTPUT_PCAP}")
    print(f"[+] Target Service: {TARGET_HOST}:{TARGET_PORT} (Direct TLS)")
    
    pcap_filter = f"tcp port {TARGET_PORT}"
    
    if os.path.exists(OUTPUT_PCAP):
        try:
            os.remove(OUTPUT_PCAP)
        except OSError:
            pass

    cmd = [
        capture_bin,
        "-f", pcap_filter,
        "-w", OUTPUT_PCAP,
        "-a", "duration:15"
    ]
    
    print(f"\n[+] Starting packet capture process...")
    try:
        capture_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except Exception as e:
        raise RuntimeError(f"Failed to start packet capture: {e}")

    time.sleep(1.5)

    print(f"[+] Initiating real TLS 1.3 POP3S connection to {TARGET_HOST}:{TARGET_PORT}...")
    try:
        ctx = ssl.create_default_context()
        pop = poplib.POP3_SSL(TARGET_HOST, TARGET_PORT, context=ctx, timeout=10)
        
        welcome = pop.getwelcome().decode('utf-8', errors='replace')
        print(f"    - Connected. Server Greeting: {welcome.strip()}")
        
        # Query capabilities if supported
        try:
            capa = pop.capa()
            print(f"    - CAPA capabilities received: {list(capa.keys())}")
        except Exception:
            pass
        
        # Graceful quit
        resp = pop.quit().decode('utf-8', errors='replace')
        print(f"    - QUIT response: {resp.strip()}")
        print(f"[+] Real POP3S session completed successfully.")
    except Exception as e:
        print(f"[!] POP3 Connection Error: {e}")
    finally:
        time.sleep(1.5)
        
        if capture_proc and capture_proc.poll() is None:
            capture_proc.terminate()
            try:
                capture_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                capture_proc.kill()

    if not os.path.exists(OUTPUT_PCAP) or os.path.getsize(OUTPUT_PCAP) == 0:
        raise RuntimeError(f"Capture failed: {OUTPUT_PCAP} was not created or is empty.")
    
    print(f"\n[+] Capture saved: {OUTPUT_PCAP} ({os.path.getsize(OUTPUT_PCAP)} bytes)")
    
    print(f"\n[+] Performing immediate forensic verification...")
    reader = PCAPReader(OUTPUT_PCAP)
    raw_pkts = reader.read_packets()
    sessions = SessionReconstructor.reconstruct_sessions(raw_pkts)
    
    print(f"    - Total packets extracted: {len(raw_pkts)}")
    print(f"    - Email sessions discovered: {len(sessions)}")
    
    if not sessions:
        print(f"[!] Warning: No POP3 sessions reconstructed. Check capture.")
        return False

    pop_session = next((s for s in sessions if s.protocol.value == "POP3"), None)
    if not pop_session:
        print(f"[!] Warning: No POP3 session found among {len(sessions)} session(s).")
        return False

    print(f"\n[+] Forensic Verification Details:")
    print(f"    - Protocol:        {pop_session.protocol.value}")
    print(f"    - Server Port:     {pop_session.server_port}")
    print(f"    - Security Mode:   {pop_session.security_mode.value}")
    print(f"    - STLS Advertised: {pop_session.starttls_state.advertised}")
    print(f"    - STLS Requested:  {pop_session.starttls_state.requested}")
    if pop_session.tls_details:
        print(f"    - TLS Version:     {pop_session.tls_details.negotiated_tls_version.value}")
        print(f"    - Cipher Suite:    {pop_session.tls_details.selected_cipher_name}")
        print(f"    - Forward Secrecy: {pop_session.tls_details.pfs_status}")
        print(f"    - Certificate:     {pop_session.tls_details.certificate_visibility}")

    print("\n" + "=" * 70)
    print(" CAPTURE COMPLETE & VALIDATED")
    print("=" * 70)
    return True


if __name__ == "__main__":
    try:
        success = capture_real_pop3_session()
        sys.exit(0 if success else 1)
    except Exception as exc:
        print(f"\n[!] Error during capture: {exc}", file=sys.stderr)
        sys.exit(1)
