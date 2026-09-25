"""
SecureMailScope X - Robust Real POP3 STLS Capture (v2)

Purpose:
- Reuse the same POP3 target configured in backend/capture_pop3_stls.py when possible.
- Capture on ALL real Npcap interfaces instead of guessing only Wi-Fi.
- Require actual STLS evidence, not merely TCP/110 SYN packets.
- Save:
    D:\SecureMailScope\pcap_samples\pop3-stls-test.pcapng
"""

import re
import ssl
import time
import poplib
import subprocess
from pathlib import Path

ROOT = Path(r"D:\SecureMailScope X")
BACKEND = ROOT / "backend"
ORIGINAL = BACKEND / "capture_pop3_stls.py"

WIRESHARK_DIR = Path(r"C:\Program Files\Wireshark")
DUMPCAP = WIRESHARK_DIR / "dumpcap.exe"
TSHARK = WIRESHARK_DIR / "tshark.exe"

OUTPUT = ROOT / "pcap_samples" / "pop3-stls-test.pcapng"

DEFAULT_HOST = "pop.gmail.com"
DEFAULT_PORT = 110


def run(cmd):
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def read_existing_target():
    host = DEFAULT_HOST
    port = DEFAULT_PORT

    if ORIGINAL.exists():
        text = ORIGINAL.read_text(encoding="utf-8", errors="replace")

        m = re.search(r'^\s*TARGET_HOST\s*=\s*[rRuUfF]*["\']([^"\']+)["\']',
                      text, re.MULTILINE)
        if m:
            host = m.group(1).strip()

        m = re.search(r'^\s*TARGET_PORT\s*=\s*(\d+)',
                      text, re.MULTILINE)
        if m:
            port = int(m.group(1))

    return host, port


def list_capture_interfaces():
    result = run([str(DUMPCAP), "-D"])
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout)

    found = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        m = re.match(r"^(\d+)\.\s+(.+)$", line)
        if not m:
            continue

        idx = m.group(1)
        lower = line.lower()

        # Exclude obvious synthetic/extcap devices where possible.
        if any(x in lower for x in (
            "bluetooth", "usbpcap", "etwdump", "sshdump",
            "randpkt", "udpdump", "ciscodump"
        )):
            continue

        # Prefer Npcap network adapters / loopback if present.
        if r"\device\npf_" in lower or "loopback" in lower or "wi-fi" in lower or "ethernet" in lower:
            found.append((idx, line))

    if not found:
        # Fall back to all numbered interfaces.
        for line in result.stdout.splitlines():
            m = re.match(r"^(\d+)\.\s+(.+)$", line.strip())
            if m:
                found.append((m.group(1), line.strip()))

    if not found:
        raise RuntimeError("No dumpcap interfaces found.")

    return found


def verify_real_stls():
    cmd = [
        str(TSHARK),
        "-r", str(OUTPUT),
        "-Y", "tcp.port == 110",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
    ]
    result = run(cmd)

    if result.returncode != 0:
        print("[!] TShark verification error:")
        print(result.stderr)
        return False

    rows = [x for x in result.stdout.splitlines() if x.strip()]

    print(f"\n[+] TCP/110 packets captured: {len(rows)}")
    for row in rows[:40]:
        print("    ", row)

    text = "\n".join(rows).upper()

    has_stls = "STLS" in text
    has_tls = (
        "CLIENT HELLO" in text
        or "SERVER HELLO" in text
        or "TLSV1.2" in text
        or "TLSV1.3" in text
        or "\tTLS\t" in text
    )

    # A real STLS trace must show the command AND subsequent TLS traffic.
    if not has_stls:
        print("\n[FAILED] No STLS command is visible in the capture.")
        return False

    if not has_tls:
        print("\n[FAILED] STLS may be visible, but no TLS handshake/traffic is visible.")
        return False

    print("\n[SUCCESS] Real POP3 STLS command + TLS upgrade evidence is present.")
    return True


def main():
    print("=" * 72)
    print("SecureMailScope X - Robust POP3 STLS Auto Capture v2")
    print("=" * 72)

    if not DUMPCAP.exists():
        raise SystemExit(f"[!] Missing: {DUMPCAP}")
    if not TSHARK.exists():
        raise SystemExit(f"[!] Missing: {TSHARK}")

    host, port = read_existing_target()
    print(f"[+] Target copied from existing project when available: {host}:{port}")

    if port != 110:
        print(f"[!] Existing TARGET_PORT is {port}; forcing STLS capture port to 110.")
        port = 110

    interfaces = list_capture_interfaces()
    print("[+] Capturing on these interfaces:")
    for idx, desc in interfaces:
        print(f"    {idx}: {desc}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    if OUTPUT.exists():
        try:
            OUTPUT.unlink()
        except PermissionError:
            raise SystemExit(
                f"[!] Cannot replace {OUTPUT}\n"
                "Close it in Wireshark and retry."
            )

    dumpcap_cmd = [str(DUMPCAP)]
    for idx, _ in interfaces:
        dumpcap_cmd += ["-i", idx]

    dumpcap_cmd += [
        "-f", "tcp port 110",
        "-w", str(OUTPUT),
        "-q",
    ]

    print(f"[+] Starting capture -> {OUTPUT}")
    capture = subprocess.Popen(
        dumpcap_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        time.sleep(2.5)

        if capture.poll() is not None:
            out, err = capture.communicate()
            raise RuntimeError(
                "dumpcap stopped before traffic generation.\n"
                + (err or out or "")
            )

        print(f"[+] Opening cleartext POP3 connection to {host}:{port} ...")
        pop = poplib.POP3(host, port, timeout=15)

        try:
            welcome = pop.getwelcome().decode("utf-8", errors="replace")
            print(f"[+] Greeting: {welcome[:180]}")
        except Exception:
            pass

        capa = pop.capa()
        capa_names = sorted(
            (k.decode() if isinstance(k, bytes) else str(k)).upper()
            for k in capa.keys()
        )
        print(f"[+] CAPA before TLS: {capa_names}")

        if "STLS" not in capa_names:
            raise RuntimeError(
                "Server did not advertise STLS. Refusing to fabricate evidence."
            )

        print("[+] STLS is advertised. Sending STLS...")
        ctx = ssl.create_default_context()
        resp = pop.stls(context=ctx)

        resp_text = (
            resp.decode("utf-8", errors="replace")
            if isinstance(resp, bytes)
            else str(resp)
        )
        print(f"[+] STLS response: {resp_text}")
        print("[+] TLS upgrade completed by poplib.")

        try:
            pop.noop()
        except Exception:
            pass

        try:
            pop.quit()
        except Exception:
            pass

        time.sleep(2.5)

    except Exception as exc:
        print(f"[!] Traffic generation error: {exc}")

    finally:
        if capture.poll() is None:
            capture.terminate()
            try:
                capture.wait(timeout=6)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.wait(timeout=3)

    time.sleep(1.0)

    if not OUTPUT.exists():
        raise SystemExit("[!] PCAPNG was not created.")

    print(f"\n[+] Capture size: {OUTPUT.stat().st_size:,} bytes")

    if verify_real_stls():
        print("\nNext command:")
        print(r"python .\backend\tests\test_smtp_starttls.py")
    else:
        print("\nDo NOT accept the POP3 STLS changes yet.")
        print("The capture does not contain enough STLS/TLS evidence.")


if __name__ == "__main__":
    main()
