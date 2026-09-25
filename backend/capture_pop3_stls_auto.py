"""
SecureMailScope X - Automatic Real POP3 STLS Capture
Captures a REAL POP3 port 110 session, CAPA/STLS negotiation, and TLS upgrade.

Output:
    D:\SecureMailScope\pcap_samples\pop3-stls-test.pcapng

Requirements:
- Wireshark installed (dumpcap.exe + tshark.exe)
- Npcap installed
- Internet connection
"""

import re
import ssl
import time
import poplib
import subprocess
from pathlib import Path

WIRESHARK_DIR = Path(r"C:\Program Files\Wireshark")
DUMPCAP = WIRESHARK_DIR / "dumpcap.exe"
TSHARK = WIRESHARK_DIR / "tshark.exe"

OUTPUT = Path(r"D:\SecureMailScope\pcap_samples\pop3-stls-test.pcapng")
POP3_HOST = "pop.gmail.com"
POP3_PORT = 110


def run(cmd):
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def find_wifi_interface():
    result = run([str(DUMPCAP), "-D"])
    if result.returncode != 0:
        raise RuntimeError(
            "Could not list capture interfaces.\n"
            + (result.stderr or result.stdout)
        )

    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]

    for line in lines:
        lower = line.lower()
        if any(k in lower for k in ("wi-fi", "wifi", "wireless", "wlan")):
            m = re.match(r"^(\d+)\.", line)
            if m:
                return m.group(1), line

    npf_lines = [line for line in lines if r"\Device\NPF_" in line]
    if len(npf_lines) == 1:
        m = re.match(r"^(\d+)\.", npf_lines[0])
        if m:
            return m.group(1), npf_lines[0]

    print("\nAvailable capture interfaces:")
    for line in lines:
        print("  ", line)

    raise RuntimeError(
        "\nCould not automatically identify the Wi-Fi interface."
    )


def verify_capture():
    result = run([
        str(TSHARK),
        "-r", str(OUTPUT),
        "-Y", "tcp.port == 110",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
    ])

    if result.returncode != 0:
        print("\n[!] TShark verification failed:")
        print(result.stderr)
        return False

    rows = [x for x in result.stdout.splitlines() if x.strip()]
    print(f"\n[+] Packets on TCP/110 captured: {len(rows)}")

    for row in rows[:20]:
        print("    ", row)

    return len(rows) > 0


def main():
    print("=" * 70)
    print("SecureMailScope X - REAL POP3 STLS Auto Capture")
    print("=" * 70)

    if not DUMPCAP.exists():
        raise SystemExit(f"[!] dumpcap.exe not found: {DUMPCAP}")
    if not TSHARK.exists():
        raise SystemExit(f"[!] tshark.exe not found: {TSHARK}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    if OUTPUT.exists():
        try:
            OUTPUT.unlink()
        except PermissionError:
            raise SystemExit(
                f"[!] Cannot replace {OUTPUT}\n"
                "Close the PCAP in Wireshark and run again."
            )

    iface_id, iface_line = find_wifi_interface()
    print(f"[+] Capture interface: {iface_line}")
    print(f"[+] Output: {OUTPUT}")
    print("[+] Capture filter: tcp port 110")

    capture = subprocess.Popen(
        [
            str(DUMPCAP),
            "-i", iface_id,
            "-f", "tcp port 110",
            "-w", str(OUTPUT),
            "-q",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        time.sleep(2.0)

        if capture.poll() is not None:
            out, err = capture.communicate()
            raise RuntimeError(
                "dumpcap stopped before capture began.\n"
                + (err or out or "")
            )

        print(f"[+] Connecting to {POP3_HOST}:{POP3_PORT} ...")
        pop = poplib.POP3(POP3_HOST, POP3_PORT, timeout=15)

        welcome = pop.getwelcome().decode("utf-8", errors="replace")
        print(f"[+] Cleartext POP3 connected: {welcome[:160]}")

        capa = pop.capa()
        capa_names = sorted(
            (k.decode() if isinstance(k, bytes) else str(k)).upper()
            for k in capa.keys()
        )
        print(f"[+] Pre-STLS CAPA: {capa_names}")

        if "STLS" not in capa_names:
            raise RuntimeError(
                "Server did not advertise STLS. Refusing to fake an upgrade."
            )

        print("[+] STLS advertised. Sending STLS command...")

        ctx = ssl.create_default_context()
        response = pop.stls(context=ctx)
        response_text = (
            response.decode("utf-8", errors="replace")
            if isinstance(response, bytes)
            else str(response)
        )
        print(f"[+] STLS accepted: {response_text}")
        print("[+] TLS upgrade completed successfully.")

        try:
            post_capa = pop.capa()
            post_names = sorted(
                (k.decode() if isinstance(k, bytes) else str(k)).upper()
                for k in post_capa.keys()
            )
            print(f"[+] Post-STLS CAPA: {post_names}")
        except Exception:
            pass

        try:
            pop.noop()
        except Exception:
            pass

        try:
            pop.quit()
        except Exception:
            pass

        time.sleep(2.0)

    except Exception as exc:
        print(f"[!] POP3 STLS error: {exc}")

    finally:
        if capture.poll() is None:
            capture.terminate()
            try:
                capture.wait(timeout=5)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.wait(timeout=3)

    time.sleep(1.0)

    if not OUTPUT.exists():
        raise SystemExit("[!] Capture file was not created.")

    size = OUTPUT.stat().st_size
    print(f"\n[+] Capture saved: {OUTPUT}")
    print(f"[+] File size: {size:,} bytes")

    if size < 1000:
        print("[!] Capture is suspiciously small.")

    if verify_capture():
        print("\n[SUCCESS] Real POP3 port 110 STLS traffic is present in the PCAPNG.")
        print("\nNext run:")
        print(r'python .\backend\tests\test_smtp_starttls.py')
    else:
        print("\n[FAILED] No TCP/110 packets were found in the capture.")
        print("Likely cause: wrong capture interface or packet-capture permission.")


if __name__ == "__main__":
    main()
