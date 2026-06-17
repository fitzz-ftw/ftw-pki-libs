# File: src/ftwpki/baselibs/signer.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2.1
"""
signer
===============================

This module provides the CertificateSigner class for issuing X.509
certificates from CSRs using a CA authority. (rw)
"""

import datetime
from pathlib import Path
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPublicKeyTypes

from ftwpki.baselibs.policies import BasePolicy
from ftwpki.baselibs.validate import validate_uri


class CertificateSigner:
    """
    Authority for signing Certificate Signing Requests. (rw)

    Acts as an issuer to transform CSRs into signed certificates,
    automatically handling AIA and CDP extensions.
    """

    def __init__(self, ca_cert: x509.Certificate, ca_key: rsa.RSAPrivateKey):
        """
        Initialize with CA certificate and private key. (rw)

        :param ca_cert: The issuer's certificate.
        :param ca_key: The issuer's private key.
        """
        self._ca_cert = ca_cert
        self._ca_key = ca_key

    def sign(
        self,
        csr: x509.CertificateSigningRequest,
        policy: BasePolicy,
        validity_days: int = 365,
        *,
        ocspURI:str="",
        crlURI:str="",
        caIssuerURI:str="",
        **kwargs,
    ) -> x509.Certificate:
        """
        Sign a certificate signing request and return a valid certificate.

        This method creates a new certificate using the subject information
        from the request. It adds extensions based on the provided policy
        and signs the final object with the certificate authority key.

        :param csr: The certificate signing request to be processed.
        :param policy: The set of rules used to generate certificate extensions.
        :param validity_days: The number of days the certificate remains valid.
        :param ocspURI: The online certificate status protocol address.
        :param crlURI: The certificate revocation list address.
        :param caIssuerURI: The address of the certificate authority issuer.
        :param kwargs: Extra settings for the policy extension generation.
        :raises UnsupportedAlgorithm: If the signature algorithm is not supported.
        :returns: The newly created and signed certificate object.
        """
        authority_info_access = ocspURI
        crl_uri = crlURI
        ca_issuer_uri = caIssuerURI

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
        builder = self._add_authority_information_access(
            builder=builder, ocsp_uri=authority_info_access, issuer_uri=ca_issuer_uri
        )
        builder = self._add_crl_distribution_points(builder, crl_uri)

        skid = x509.SubjectKeyIdentifier.from_public_key(public_key)
        builder = builder.add_extension(skid, critical=False)

        return builder.sign(self._ca_key, hashes.SHA512())

    def get_pem(self, cert: x509.Certificate) -> bytes:
        """
        Serialize the certificate to PEM format. (ro)

        :param cert: The certificate object to serialize.
        :returns: PEM encoded bytes.
        """
        return cert.public_bytes(serialization.Encoding.PEM)

    def __repr__(self) -> str:
        """
        Return the canonical string representation. (rw)

        :returns: String containing the class name and issuer.
        """
        return f"{self.__class__.__name__}(issuer={self._ca_cert.subject})"

    def _add_authority_information_access(
        self, builder: x509.CertificateBuilder, ocsp_uri: str = "", issuer_uri: str = ""
    ) -> x509.CertificateBuilder:
        """
        Adds the AIA extension (OCSP and/or CA Issuers). (rw)
        """
        descriptions: list[x509.AccessDescription] = []
        if ocsp_uri := validate_uri(ocsp_uri.strip(), True, "oscp").strip():
            descriptions.append(
                x509.AccessDescription(x509.OID_OCSP, x509.UniformResourceIdentifier(ocsp_uri))
            )
        if issuer_uri := validate_uri(issuer_uri.strip()).strip():
            descriptions.append(
                x509.AccessDescription(
                    x509.OID_CA_ISSUERS, x509.UniformResourceIdentifier(issuer_uri)
                )
            )

        if descriptions:
            builder = builder.add_extension(
                x509.AuthorityInformationAccess(descriptions), critical=False
            )
        return builder

    def _add_crl_distribution_points(
        self, builder: x509.CertificateBuilder, crl_uri: str = ""
    ) -> x509.CertificateBuilder:
        """
        Adds the CRL Distribution Points (CDP) extension. (rw)
        """
        if validated_crl := validate_uri(crl_uri, no_https=True, uri_type="crl"):
            dist_point = x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(validated_crl)],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
            builder = builder.add_extension(
                x509.CRLDistributionPoints([dist_point]), critical=False
            )
        return builder


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
