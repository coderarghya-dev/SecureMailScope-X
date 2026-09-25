"""
SecureMailScope X - TLS Dissector

Extracts TLS ClientHello / ServerHello evidence, negotiated protocol
version, cipher suite, SNI, ALPN and observable Forward Secrecy evidence.
"""

from typing import Optional

from ..schemas.forensic import TLSHandshakeDetails, TLSVersion
from .cipher_suites import lookup_cipher_suite


VERSION_MAP = {
    "0x0304": TLSVersion.TLSv1_3,
    "0x0303": TLSVersion.TLSv1_2,
    "0x0302": TLSVersion.TLSv1_1,
    "0x0301": TLSVersion.TLSv1_0,
    "0x0300": TLSVersion.SSLv3,
    "0x0200": TLSVersion.SSLv2,

    "772": TLSVersion.TLSv1_3,
    "771": TLSVersion.TLSv1_2,
    "770": TLSVersion.TLSv1_1,
    "769": TLSVersion.TLSv1_0,
}


# TLS 1.3 cipher-suite codepoints.
# These are separate from the key-exchange mechanism.
TLS13_CIPHER_CODES = {
    0x1301,  # TLS_AES_128_GCM_SHA256
    0x1302,  # TLS_AES_256_GCM_SHA384
    0x1303,  # TLS_CHACHA20_POLY1305_SHA256
    0x1304,  # TLS_AES_128_CCM_SHA256
    0x1305,  # TLS_AES_128_CCM_8_SHA256
}


class TLSDissector:

    @staticmethod
    def _parse_tls_version(value: Optional[str]) -> TLSVersion:
        """
        Convert TShark/Wireshark version representations into TLSVersion.
        """
        if value is None:
            return TLSVersion.UNKNOWN

        text = str(value).strip().lower()

        if not text:
            return TLSVersion.UNKNOWN

        # Prefer explicit TLS text.
        if "tls 1.3" in text or "tlsv1.3" in text:
            return TLSVersion.TLSv1_3

        if "tls 1.2" in text or "tlsv1.2" in text:
            return TLSVersion.TLSv1_2

        if "tls 1.1" in text or "tlsv1.1" in text:
            return TLSVersion.TLSv1_1

        if "tls 1.0" in text or "tlsv1.0" in text:
            return TLSVersion.TLSv1_0

        # Wireshark may return textual strings containing the raw value.
        if "0x0304" in text:
            return TLSVersion.TLSv1_3

        if "0x0303" in text:
            return TLSVersion.TLSv1_2

        if "0x0302" in text:
            return TLSVersion.TLSv1_1

        if "0x0301" in text:
            return TLSVersion.TLSv1_0

        # Exact decimal / hex forms.
        if text in VERSION_MAP:
            return VERSION_MAP[text]

        return TLSVersion.UNKNOWN

    @staticmethod
    def _cipher_code_to_int(cipher_code: Optional[str]) -> Optional[int]:
        """
        Convert cipher representations such as:
        0x1301
        4865
        into an integer.
        """
        if cipher_code is None:
            return None

        value = str(cipher_code).strip().lower()

        try:
            if value.startswith("0x"):
                return int(value, 16)

            return int(value, 10)

        except (TypeError, ValueError):
            return None

    @classmethod
    def _is_tls13_cipher(
        cls,
        cipher_code: Optional[str],
        cipher_name: Optional[str],
    ) -> bool:
        """
        TLS 1.3 cipher suites provide useful fallback evidence when the
        ServerHello supported_versions field was not supplied upstream.
        """

        code_int = cls._cipher_code_to_int(cipher_code)

        if code_int in TLS13_CIPHER_CODES:
            return True

        if cipher_name:
            name = str(cipher_name).upper()

            tls13_prefixes = (
                "TLS_AES_",
                "TLS_CHACHA20_",
            )

            if name.startswith(tls13_prefixes):
                return True

        return False

    @classmethod
    def dissect_handshake(
        cls,
        client_hello_frame: Optional[int],
        client_hello_time: Optional[float],
        server_hello_frame: Optional[int],
        server_hello_time: Optional[float],
        sni: Optional[str],
        alpn: Optional[str],
        raw_version: Optional[str],
        supported_version_ext: Optional[str],
        cipher_code: Optional[str],
        cipher_name: Optional[str] = None,
        key_share_group: Optional[str] = None,
        server_share_group: Optional[str] = None,
        key_share_observed: bool = False,
        server_kx_observed: bool = False,
    ) -> TLSHandshakeDetails:

        details = TLSHandshakeDetails(
            sni=sni,
            alpn=alpn,
            client_hello_frame=client_hello_frame,
            client_hello_time=client_hello_time,
            server_hello_frame=server_hello_frame,
            server_hello_time=server_hello_time,
        )

        # ==========================================================
        # 1. DETERMINE THE ACTUAL NEGOTIATED TLS VERSION
        # ==========================================================
        #
        # TLS 1.3 ServerHello keeps legacy_version = 0x0303.
        #
        # Therefore:
        #
        # ServerHello supported_versions
        #          ↓
        # TLS-1.3-only cipher evidence
        #          ↓
        # legacy/raw version
        #
        # Never prefer 0x0303 over explicit TLS 1.3 evidence.
        # ==========================================================

        negotiated_ver = TLSVersion.UNKNOWN

        # PRIMARY:
        # ServerHello supported_versions selected value.
        if supported_version_ext:
            negotiated_ver = cls._parse_tls_version(
                supported_version_ext
            )

        # SECONDARY:
        # TLS 1.3 cipher suites are TLS-1.3-specific.
        #
        # This protects us when TShark extracted the ServerHello but
        # the upstream parser failed to pass supported_version_ext.
        if (
            negotiated_ver == TLSVersion.UNKNOWN
            and cls._is_tls13_cipher(cipher_code, cipher_name)
        ):
            negotiated_ver = TLSVersion.TLSv1_3

        # LAST FALLBACK:
        # Legacy handshake / record version.
        if (
            negotiated_ver == TLSVersion.UNKNOWN
            and raw_version
        ):
            negotiated_ver = cls._parse_tls_version(raw_version)

        details.negotiated_tls_version = negotiated_ver
        details.server_version_negotiated = negotiated_ver.value

        # ==========================================================
        # 2. CIPHER SUITE
        # ==========================================================

        code_to_check = cipher_code or cipher_name
        cipher_info = None

        if code_to_check:
            cipher_info = lookup_cipher_suite(
                str(code_to_check)
            )

            if cipher_info:
                details.cipher_info = cipher_info
                details.selected_cipher_code = cipher_info.hex_code
                details.selected_cipher_name = cipher_info.name

        # ==========================================================
        # 3. PERFECT FORWARD SECRECY
        # ==========================================================
        #
        # IMPORTANT:
        # Do NOT infer PFS solely because TLS 1.3 was negotiated.
        #
        # PFS requires observable ephemeral key-exchange evidence.
        # ==========================================================

        if (
            key_share_group
            or server_share_group
        ):
            group_name = (
                server_share_group
                or key_share_group
            )

            details.has_forward_secrecy = True
            details.pfs_status = (
                f"Yes (Observable key_share: {group_name})"
            )

            details.pfs_evidence = (
                f"Key Share extension observed with group "
                f"{group_name}"
            )

            details.selected_group = group_name
            details.key_share_observed = True

        elif (
            cipher_info
            and cipher_info.has_pfs is True
            and (
                server_kx_observed
                or "ecdhe" in (cipher_info.name or "").lower()
                or "dhe" in (cipher_info.name or "").lower()
            )
        ):
            details.has_forward_secrecy = True

            details.pfs_status = (
                f"Yes (Observable {cipher_info.key_exchange})"
            )

            details.pfs_evidence = (
                f"Cipher suite {cipher_info.name} with observable "
                f"ephemeral key exchange"
            )

        # IMPORTANT:
        # TLS 1.3 cipher suites do NOT themselves encode the
        # key-exchange algorithm.
        #
        # If key_share is missing, do not claim "No PFS".
        elif negotiated_ver == TLSVersion.TLSv1_3:

            details.has_forward_secrecy = None

            details.pfs_status = (
                "Unknown / insufficient passive evidence"
            )

            details.pfs_evidence = (
                "TLS 1.3 observed, but key_share / ephemeral "
                "key-exchange evidence was not available to the "
                "parser"
            )

        elif cipher_info and cipher_info.has_pfs is False:

            details.has_forward_secrecy = False

            details.pfs_status = (
                f"No ({cipher_info.key_exchange} - "
                f"Static Key Exchange)"
            )

            details.pfs_evidence = (
                f"Cipher suite {cipher_info.name} uses static "
                f"key exchange without Forward Secrecy"
            )

        else:
            details.has_forward_secrecy = None

            details.pfs_status = (
                "Unknown / insufficient passive evidence"
            )

            details.pfs_evidence = (
                "Handshake key-share or ephemeral key-exchange "
                "parameters were not observable in the passive "
                "capture"
            )

        # ==========================================================
        # 4. CERTIFICATE VISIBILITY
        # ==========================================================

        if negotiated_ver == TLSVersion.TLSv1_3:

            details.certificate_visibility = (
                "Unavailable from passive capture "
                "(TLS 1.3 encrypted handshake)"
            )

        else:

            details.certificate_visibility = (
                "Unavailable from passive capture"
            )

        return details