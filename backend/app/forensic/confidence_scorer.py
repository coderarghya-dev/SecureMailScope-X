"""
SecureMailScope X - Evidence Confidence Scorer
Quantifies cryptographic observability and respects RFC 8446 protocol encryption boundaries.
"""

from typing import Optional, List
from ..schemas.forensic import (
    EvidenceConfidence,
    ConfidenceLevel,
    TLSHandshakeDetails,
    TLSVersion,
    SecurityMode
)


class ConfidenceScorer:
    @classmethod
    def calculate_confidence(
        cls,
        tls_details: Optional[TLSHandshakeDetails],
        security_mode: SecurityMode
    ) -> EvidenceConfidence:
        """
        Evaluate observability confidence based strictly on verified packet evidence.
        """
        factors: List[str] = []

        if not tls_details:
            if security_mode == SecurityMode.PLAINTEXT:
                return EvidenceConfidence(
                    score=100,
                    level=ConfidenceLevel.HIGH,
                    handshake_observable=False,
                    version_verifiable=False,
                    cipher_identifiable=False,
                    key_exchange_observable=False,
                    observability_boundary="None (Plaintext session - unencrypted traffic directly inspectable)",
                    confidence_factors=["Full plaintext payload directly observable from packet capture"]
                )
            else:
                return EvidenceConfidence(
                    score=60,
                    level=ConfidenceLevel.MEDIUM,
                    handshake_observable=False,
                    version_verifiable=False,
                    cipher_identifiable=False,
                    key_exchange_observable=False,
                    observability_boundary="No TLS handshake captured within stream",
                    confidence_factors=["Protocol state transitions observed, but TLS handshake absent"]
                )

        score = 0
        handshake_obs = bool(tls_details.client_hello_frame and tls_details.server_hello_frame)
        if handshake_obs:
            score += 35
            factors.append(
                f"Complete TLS Handshake observed "
                f"(ClientHello Frame {tls_details.client_hello_frame} "
                f"→ ServerHello Frame {tls_details.server_hello_frame})"
            )
        elif tls_details.client_hello_frame or tls_details.server_hello_frame:
            score += 20
            factors.append("Partial TLS Handshake frames observed")

        version_ver = tls_details.negotiated_tls_version != TLSVersion.UNKNOWN
        if version_ver:
            score += 25
            factors.append(
                f"Authoritative TLS version negotiated: "
                f"{tls_details.negotiated_tls_version.value}"
            )

        cipher_id = bool(
            tls_details.selected_cipher_name
            or tls_details.selected_cipher_code
        )

        if cipher_id:
            score += 20
            factors.append(
                f"IANA Cipher Suite identified: "
                f"{tls_details.selected_cipher_name or tls_details.selected_cipher_code}"
            )

        kex_obs = bool(
            tls_details.key_share_observed
            or (tls_details.has_forward_secrecy is not None)
        )

        if kex_obs:
            score += 20
            factors.append(
                f"Key Exchange / Forward Secrecy evidence verified: "
                f"{tls_details.pfs_status}"
            )
        else:
            factors.append(
                "Key exchange / Forward Secrecy could not be verified from observable passive evidence"
            )

        boundary = None

        if tls_details.negotiated_tls_version == TLSVersion.TLSv1_3:
            boundary = (
                "RFC 8446 Encrypted Handshake "
                "(Server certificates and post-ServerHello extensions are encrypted by design)"
            )

        elif tls_details.negotiated_tls_version == TLSVersion.TLSv1_2:
            boundary = (
                "RFC 5246 Standard Handshake "
                "(Plaintext certificate exchange)"
            )

        score = max(0, min(100, score))

        if score >= 80:
            level = ConfidenceLevel.HIGH
        elif score >= 50:
            level = ConfidenceLevel.MEDIUM
        else:
            level = ConfidenceLevel.LOW

        return EvidenceConfidence(
            score=score,
            level=level,
            handshake_observable=handshake_obs,
            version_verifiable=version_ver,
            cipher_identifiable=cipher_id,
            key_exchange_observable=kex_obs,
            observability_boundary=boundary,
            confidence_factors=factors
        )