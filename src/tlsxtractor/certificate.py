"""
X.509 certificate parsing and domain extraction.
"""

from typing import Any, Dict, List

from cryptography import x509
from cryptography.hazmat.backends import default_backend


class CertificateParser:
    """
    Parses X.509 certificates to extract domain information.

    Implements Tasks IMPL-007 and IMPL-008:
    - X.509 certificate retrieval
    - Subject Alternative Names (SAN) extraction
    """

    @staticmethod
    def parse_certificate(cert_der: bytes) -> Dict[str, Any]:
        """
        Parse a DER-encoded certificate.

        Args:
            cert_der: Certificate in DER format

        Returns:
            Dictionary containing parsed certificate data
        """
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())

            return {
                "subject": CertificateParser._extract_subject(cert),
                "san": CertificateParser._extract_san(cert),
                "issuer": CertificateParser._extract_issuer(cert),
                "validity": CertificateParser._extract_validity(cert),
            }
        except Exception as e:
            return {"error": f"Certificate parsing failed: {str(e)}"}

    @staticmethod
    def _extract_subject(cert: x509.Certificate) -> Dict[str, str]:
        """Extract subject information from certificate."""
        subject = {}
        for attr in cert.subject:
            subject[attr.oid._name] = attr.value
        return subject

    @staticmethod
    def _extract_san(cert: x509.Certificate) -> List[str]:
        """
        Extract Subject Alternative Names from certificate.

        Returns:
            List of DNS names from SAN extension
        """
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            # san_ext.value is SubjectAlternativeName
            san_value: x509.SubjectAlternativeName = san_ext.value  # type: ignore[assignment]
            san_list = [str(name) for name in san_value.get_values_for_type(x509.DNSName)]
            return san_list
        except x509.ExtensionNotFound:
            # No SAN extension, try Common Name
            try:
                cn_attrs = cert.subject.get_attributes_for_oid(
                    x509.oid.NameOID.COMMON_NAME
                )
                cn = str(cn_attrs[0].value)
                return [cn]
            except (IndexError, KeyError):
                return []

    @staticmethod
    def _extract_issuer(cert: x509.Certificate) -> Dict[str, str]:
        """Extract issuer information from certificate."""
        issuer = {}
        for attr in cert.issuer:
            issuer[attr.oid._name] = attr.value
        return issuer

    @staticmethod
    def _extract_validity(cert: x509.Certificate) -> Dict[str, str]:
        """Extract validity period from certificate."""
        return {
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
        }
