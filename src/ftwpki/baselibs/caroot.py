# File: src/ftwpki/baselibs/caroot.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2.1
"""
caroot
===============================


Modul caroot documentation
"""

import datetime
from pathlib import Path
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
    PrivateKeyTypes,
)

from ftwpki.baselibs.core import create_distinguished_name, generate_rsa_key_pair


class CertificateAuthority:
    """
    Handles the creation of Root CAs and certificate management.
    """

    def __init__(
        self,
        common_name: str,
        country: str,
        state: str,
        location: str,
        organization: str,
        organizational_unit: str = ".",
    ) -> None:
        """
        Initialize CA metadata based on constants.

        The dot ('.') in organizational_unit prevents the field from being created.

        :param common_name: The fullname of the CA.
        :param country: Two-letter country code.
        :param state: State or province.
        :param location: Locality or city.
        :param organization: Organization name.
        :param organizational_unit: Organization Unit.
        """
        self._subject = create_distinguished_name(
            common_name=common_name,
            country=country,
            state=state,
            location=location,
            organization=organization,
            organizational_unit=organizational_unit,
        )
        self._private_key: bytes = b""
        self._ca_cert: bytes = b""
        self._public_key: bytes = b""

    @property
    def private_key(self) -> bytes:
        return self._private_key

    @property
    def public_key(self) -> bytes:
        return self._public_key

    def certificate(self) -> bytes:
        return self._ca_cert

    def generate_key_pair(self, passphrase: str) -> None:
        """
        Generate a 4096-bit RSA key and encrypt it manually using AES-256-CBC.

        The resulting byte string follows a custom deterministic format:
        [16 bytes Salt] + [16 bytes IV] + [AES-256-CBC Encrypted PKCS7-padded PEM]

        Key Derivation: PBKDF2-HMAC-SHA256, 600,000 iterations.

        :param passphrase: The strong passphrase for encryption.
        :raises ValueError: If passphrase is empty or '.'.
        :returns: Composite byte string (Salt | IV | Ciphertext).
        """
        if not passphrase or passphrase == ".":
            raise ValueError("Root CA private key MUST be protected by a strong passphrase.")

        private_pem, public_pem = generate_rsa_key_pair(passphrase)

        # Die CA-Instanz merkt sich die Ergebnisse
        self._private_key = private_pem
        self._public_key = public_pem

    def create_root_certificate(self, passphrase: str, days: int = 7300) -> None:
        """
        Create a self-signed Root CA certificate (v3_ca_cert).

        :param private_key_bytes: The PEM encoded private key.
        :param passphrase: Password for the private key.
        :param days: Validity period (default 7300 / 20 years).
        :returns: The certificate in PEM format.
        """
        if not self._private_key:
            self.generate_key_pair(passphrase=passphrase)

        private_key: PrivateKeyTypes = serialization.load_pem_private_key(
            self._private_key, password=passphrase.encode()
        )
        public_key = cast(CertificatePublicKeyTypes, private_key.public_key())

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(self._subject)
        builder = builder.issuer_name(self._subject)  # Self-signed
        builder = builder.public_key(public_key)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        builder = builder.not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
        )

        # Add extensions equivalent to [ v3_ca_cert ]
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )

        issuer_key = cast(CertificateIssuerPrivateKeyTypes, private_key)

        certificate = builder.sign(
            private_key=issuer_key,
            algorithm=hashes.SHA512(),  # matching default_md
        )

        self._ca_cert = certificate.public_bytes(serialization.Encoding.PEM)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(subject={self._subject!r})"


if __name__ == "__main__":  # pragma: no cover
    from doctest import FAIL_FAST, testfile

    be_verbose = False
    be_verbose = True
    option_flags = 0
    option_flags = FAIL_FAST
    test_sum = 0
    test_failed = 0

    # Pfad zu den dokumentierenden Tests
    testfiles_dir = Path(__file__).parents[3] / "doc/source/devel"
    test_file = testfiles_dir / "get_started_caroot.rst"

    if test_file.exists():
        print(f"--- Running Doctest for {test_file.name} ---")
        doctestresult = testfile(
            str(test_file),
            module_relative=False,
            verbose=be_verbose,
            optionflags=option_flags,
        )
        test_failed += doctestresult.failed
        test_sum += doctestresult.attempted
        if test_failed == 0:
            print(f"\nDocTests passed without errors, {test_sum} tests.")
        else:
            print(f"\nDocTests failed: {test_failed} tests.")
    else:
        print(f"⚠️ Warning: Test file {test_file.name} not found.")
