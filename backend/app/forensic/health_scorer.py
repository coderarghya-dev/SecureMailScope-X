"""
SecureMailScope X - Capture Health Scorer
Quantifies PCAP capture quality, stream completeness, and packet transmission health.
"""

from typing import List, Dict, Any
from ..schemas.forensic import CaptureHealth, HealthGrade


class HealthScorer:
    @classmethod
    def calculate_health(
        cls,
        raw_packets: List[Dict[str, Any]],
        syn_observed: bool,
        fin_rst_observed: bool,
        duration_seconds: float = 0.0
    ) -> CaptureHealth:
        """
        Evaluate stream completeness and network quality from packet evidence.
        """
        score = 100
        deductions: List[str] = []
        total_pkts = len(raw_packets)

        # 1. 3-Way Handshake Completeness
        if not syn_observed:
            score -= 20
            deductions.append("TCP 3-way handshake (SYN) not observed (session captured mid-stream)")

        # 2. Connection Teardown Completeness
        if not fin_rst_observed:
            score -= 15
            deductions.append("TCP connection teardown (FIN/RST) not observed (capture truncated)")

        # 3. Retransmissions and Packet Drops
        retrans_count = 0
        for p in raw_packets:
            info = str(p.get("info") or "")
            if "[TCP Retransmission]" in info or "[TCP Fast Retransmission]" in info or "[TCP Spurious Retransmission]" in info or "[TCP Dup ACK]" in info:
                retrans_count += 1

        retrans_rate = (retrans_count / total_pkts) if total_pkts > 0 else 0.0

        if retrans_rate > 0.20:
            score -= 25
            deductions.append(f"High TCP retransmission / packet loss rate: {retrans_rate:.1%} ({retrans_count} retransmissions)")
        elif retrans_rate > 0.05:
            score -= 10
            deductions.append(f"Moderate TCP retransmission rate: {retrans_rate:.1%} ({retrans_count} retransmissions)")

        # 4. Stream Packet Volume Sanity
        if total_pkts < 3:
            score -= 15
            deductions.append(f"Abnormally low packet count ({total_pkts} packets in stream)")

        score = max(0, min(100, score))

        if score >= 90:
            grade = HealthGrade.EXCELLENT
        elif score >= 75:
            grade = HealthGrade.GOOD
        elif score >= 50:
            grade = HealthGrade.FAIR
        else:
            grade = HealthGrade.DEGRADED

        return CaptureHealth(
            score=score,
            grade=grade,
            syn_observed=syn_observed,
            fin_rst_observed=fin_rst_observed,
            total_packets=total_pkts,
            retransmissions_count=retrans_count,
            retransmission_rate=round(retrans_rate, 4),
            deduction_reasons=deductions
        )
