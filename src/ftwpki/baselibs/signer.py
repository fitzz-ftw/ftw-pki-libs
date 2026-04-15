# File: src/ftwpki/baselibs/signer.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2.1
"""
signer
===============================


Modul signer documentation
"""

import datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPublicKeyTypes
from cryptography.x509.oid import AuthorityInformationAccessOID

from ftwpki.baselibs.policies import BasePolicy


class CertificateSigner:
    """
    Authority for signing Certificate Signing Requests.
    """

    def __init__(self, ca_cert: x509.Certificate, ca_key):
        """
        Initialize with CA certificate and private key.

        :param ca_cert: The issuer's certificate.
        :param ca_key: The issuer's private key.
        """
        self._ca_cert = ca_cert
        self._ca_key = ca_key

    def sign(self, csr: x509.CertificateSigningRequest, 
             policy: BasePolicy, 
             validity_days: int = 365, **kwargs) -> x509.Certificate:
        """
        Sign a CSR and return a valid certificate.

        :param csr: The request to be signed.
        :param policy: The policy used to generate final extensions.
        :param validity_days: Number of days the certificate is valid.
        :raises cryptography.exceptions.UnsupportedAlgorithm: If the signature algorithm is 
                unsupported.
        :returns: The signed certificate object.
        """
        authority_info_access = kwargs.pop("authorityInfoAccess", None)
        public_key = csr.public_key()
        
        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=validity_days)
            )
        )

        # Apply extensions from the provided policy
        for ext, critical in policy.get_extensions(**kwargs):
            builder = builder.add_extension(ext, critical=critical)

        # Authority Key Identifier from CA certificate
        ca_public_key = cast(CertificateIssuerPublicKeyTypes, self._ca_cert.public_key())
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_public_key)
        builder = builder.add_extension(aki, critical=False)

        builder = self._add_aia_extension(builder=builder, aia_uri=authority_info_access)

        return builder.sign(self._ca_key, hashes.SHA512())

    def get_pem(self, cert: x509.Certificate) -> bytes:
        """
        Serialize the certificate to PEM format.

        :param cert: The certificate object to serialize.
        :returns: PEM encoded bytes.
        """
        return cert.public_bytes(serialization.Encoding.PEM)

    def __repr__(self) -> str:
        """
        Return the canonical string representation.

        :returns: String containing the class name and issuer.
        """
        return f"{self.__class__.__name__}(issuer={self._ca_cert.subject})"

    def _add_aia_extension(self, builder, aia_uri: str | None):
        """
        Adds the AIA extension for OCSP.
        Skips if aia_uri is empty, invalid, or uses HTTPS (to avoid circular dependencies).
        """
        if not aia_uri or not aia_uri.strip():
            return builder

        # Extraktion der URL (unterstützt "OCSP;URI:http://..." oder "http://...")
        url_candidate = aia_uri.split("URI:")[-1].strip()

        try:
            parsed = urlparse(url_candidate)

            # 1. Validitäts-Check (Schema und Host müssen da sein)
            if not all([parsed.scheme, parsed.netloc]):
                print(f"Warning: '{url_candidate}' is not a valid absolute URL.")
                return builder

            # 2. Endlosschleifen-Prävention: HTTPS verbieten
            if parsed.scheme.lower() == "https":
                print(
                    f"Error: OCSP URI must be HTTP to avoid circular dependencies! Skipping: {url_candidate}"  # noqa: E501
                )
                return builder

            # 3. Optional: Nur HTTP erlauben (falls jemand ftp:// oder ähnliches versucht)
            if parsed.scheme.lower() != "http":
                print(f"Warning: URI scheme '{parsed.scheme}' is unusual for OCSP. Skipping.")
                return builder

            builder = builder.add_extension(
                x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            AuthorityInformationAccessOID.OCSP,
                            x509.UniformResourceIdentifier(url_candidate),
                        )
                    ]
                ),
                critical=False,
            )
        except Exception as e:
            print(f"Warning: Could not process AIA URI '{aia_uri}': {e}")

        return builder


if __name__ == "__main__": # pragma: no cover
    from doctest import FAIL_FAST, testfile
    
    be_verbose = False
    be_verbose = True
    option_flags = 0
    option_flags = FAIL_FAST
    test_sum = 0
    test_failed = 0
    
    # Pfad zu den dokumentierenden Tests
    testfiles_dir = Path(__file__).parents[3] / "doc/source/devel"
    test_file = testfiles_dir / "get_started_signer.rst"
    
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
