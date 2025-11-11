"""
Unit tests for certificate parser.
"""

import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tlsxtractor.certificate import CertificateParser


def create_test_certificate():
    """Create a test self-signed certificate."""
    # Generate key
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    # Certificate details
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ]
    )

    # Build certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("test.example.com"),
                    x509.DNSName("*.test.example.com"),
                    x509.DNSName("another.example.com"),
                ]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), backend=default_backend())
    )

    from cryptography.hazmat.primitives import serialization

    return cert.public_bytes(encoding=serialization.Encoding.DER)


def test_parse_certificate():
    """Test parsing a valid certificate."""
    cert_der = create_test_certificate()
    cert_info = CertificateParser.parse_certificate(cert_der)

    assert "subject" in cert_info
    assert "san" in cert_info
    assert "issuer" in cert_info
    assert "validity" in cert_info


def test_extract_san():
    """Test extracting Subject Alternative Names."""
    cert_der = create_test_certificate()
    cert_info = CertificateParser.parse_certificate(cert_der)

    san_list = cert_info.get("san", [])
    assert len(san_list) == 3
    assert "test.example.com" in san_list
    assert "*.test.example.com" in san_list
    assert "another.example.com" in san_list


def test_extract_subject():
    """Test extracting certificate subject."""
    cert_der = create_test_certificate()
    cert_info = CertificateParser.parse_certificate(cert_der)

    subject = cert_info.get("subject", {})
    assert "commonName" in subject
    assert subject["commonName"] == "test.example.com"
    assert subject.get("organizationName") == "Test Org"


def test_extract_validity():
    """Test extracting validity period."""
    cert_der = create_test_certificate()
    cert_info = CertificateParser.parse_certificate(cert_der)

    validity = cert_info.get("validity", {})
    assert "not_before" in validity
    assert "not_after" in validity
    # Should be ISO format dates
    assert "T" in validity["not_before"]
    assert "T" in validity["not_after"]
