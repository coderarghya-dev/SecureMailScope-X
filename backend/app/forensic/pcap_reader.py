"""
SecureMailScope X - Passive PCAP Forensics Reader
Extracts packet frames, TCP stream sessions, protocol metadata, and TLS parameters.
"""

import os
import subprocess
import json
from typing import Dict, List, Optional, Any
from ..core.tshark_detector import TSharkDetector
from ..schemas.forensic import PacketEvidence


# Known email ports
SMTP_PORTS = {25, 465, 587}
IMAP_PORTS = {143, 993}
POP3_PORTS = {110, 995}
ALL_EMAIL_PORTS = SMTP_PORTS | IMAP_PORTS | POP3_PORTS


class PCAPReader:
    def __init__(self, pcap_path: str):
        if not os.path.isfile(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        self.pcap_path = pcap_path
        self.tshark_path = TSharkDetector.find_tshark()

    def read_packets(self) -> List[Dict[str, Any]]:
        """
        Extract structured packet information from the PCAP using TShark.
        Returns a list of parsed packet dictionaries.
        """
        if not self.tshark_path:
            raise RuntimeError("TShark binary is required for forensic packet dissection.")

        # Fields to extract (100% standard across all Wireshark / TShark versions)
        fields = [
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.stream",
            "-e", "_ws.col.Protocol",
            "-e", "tcp.flags.syn",
            "-e", "tcp.flags.fin",
            "-e", "tcp.flags.reset",
            "-e", "tls.handshake.type",
            "-e", "tls.handshake.version",
            "-e", "tls.handshake.ciphersuite",
            "-e", "tls.handshake.extensions_server_name",
            "-e", "tls.record.version",
            "-e", "tls.handshake.extension.type",
            "-e", "tls.handshake.certificate",
            "-e", "_ws.col.Info"
        ]

        # Filter for email-relevant ports or protocols to optimize execution time
        display_filter = (
            "tcp.port in {25, 465, 587, 143, 993, 110, 995} || smtp || imap || pop"
        )

        cmd = [
            self.tshark_path,
            "-r", self.pcap_path,
            "-Y", display_filter,
            "-T", "fields",
            "-E", "separator=/t",
            "-E", "quote=d",
            "-E", "occurrence=a"
        ] + fields

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
                check=True
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"TShark timed out while reading {self.pcap_path}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"TShark extraction failed: {e.stderr}")

        packets = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            parts = line.split("\t")
            # Strip quotes
            clean_parts = [p.strip('"') for p in parts]
            if len(clean_parts) < 8:
                continue

            frame_num_str = clean_parts[0] if len(clean_parts) > 0 else "0"
            time_epoch_str = clean_parts[1] if len(clean_parts) > 1 else "0.0"
            ip_src = clean_parts[2] if len(clean_parts) > 2 else ""
            ip_dst = clean_parts[3] if len(clean_parts) > 3 else ""
            src_port_str = clean_parts[4] if len(clean_parts) > 4 else "0"
            dst_port_str = clean_parts[5] if len(clean_parts) > 5 else "0"
            stream_id_str = clean_parts[6] if len(clean_parts) > 6 else "-1"
            col_protocol = clean_parts[7] if len(clean_parts) > 7 else ""
            tcp_syn = clean_parts[8] if len(clean_parts) > 8 else "0"
            tcp_fin = clean_parts[9] if len(clean_parts) > 9 else "0"
            tcp_rst = clean_parts[10] if len(clean_parts) > 10 else "0"
            tls_handshake_type = clean_parts[11] if len(clean_parts) > 11 else ""
            tls_handshake_ver = clean_parts[12] if len(clean_parts) > 12 else ""
            tls_ciphersuite = clean_parts[13] if len(clean_parts) > 13 else ""
            tls_sni = clean_parts[14] if len(clean_parts) > 14 else ""
            tls_rec_ver = clean_parts[15] if len(clean_parts) > 15 else ""
            tls_ext_type = clean_parts[16] if len(clean_parts) > 16 else ""
            tls_certificate = clean_parts[17] if len(clean_parts) > 17 else ""
            col_info = clean_parts[18] if len(clean_parts) > 18 else (clean_parts[17] if len(clean_parts) > 17 else "")

            try:
                frame_number = int(frame_num_str)
                timestamp_epoch = float(time_epoch_str)
                src_port = int(src_port_str) if src_port_str.isdigit() else 0
                dst_port = int(dst_port_str) if dst_port_str.isdigit() else 0
                stream_id = int(stream_id_str) if stream_id_str.lstrip("-").isdigit() else -1
            except ValueError:
                continue

            packets.append({
                "frame_number": frame_number,
                "timestamp_epoch": timestamp_epoch,
                "src_ip": ip_src,
                "src_port": src_port,
                "dst_ip": ip_dst,
                "dst_port": dst_port,
                "stream_id": stream_id,
                "protocol": col_protocol,
                "info": col_info,
                "is_syn": tcp_syn in ["1", "True"] or "1" in tcp_syn.split(",") or "[SYN]" in col_info or "[SYN, ACK]" in col_info,
                "is_fin": tcp_fin in ["1", "True"] or "1" in tcp_fin.split(",") or "[FIN]" in col_info or "[FIN, ACK]" in col_info,
                "is_rst": tcp_rst in ["1", "True"] or "1" in tcp_rst.split(",") or "[RST]" in col_info or "[RST, ACK]" in col_info,
                "tls_handshake_type": tls_handshake_type,
                "tls_handshake_version": tls_handshake_ver,
                "tls_ciphersuite": tls_ciphersuite,
                "tls_sni": tls_sni,
                "tls_record_version": tls_rec_ver,
                "tls_extension_types": tls_ext_type,
                "tls_certificate": tls_certificate
            })

        return packets

    def get_raw_packet_count(self) -> int:
        """
        Get total raw packet/frame count from the capture file before display filtering.
        """
        if not self.tshark_path:
            return 0
        cmd = [
            self.tshark_path,
            "-r", self.pcap_path,
            "-q",
            "-z", "io,stat,0"
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15
            )
            import re
            match = re.search(r'\|\s+[\d\.]+\s+<>\s+[\d\.]+\s+\|\s+(\d+)\s+\|', result.stdout)
            if match:
                return int(match.group(1))
        except Exception:
            pass
        return 0

