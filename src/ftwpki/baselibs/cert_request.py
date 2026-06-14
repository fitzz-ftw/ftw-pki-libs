# File: src/ftwpki/baselibs/request.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2.1
"""
request
===============================

This module handles the creation and serialization of X.509 Certificate
Signing Requests (CSR) using defined policies. (rw)
"""

from pathlib import Path
from typing import Self

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from ftwpki.baselibs.policies import BasePolicy


# CLASS - CertificateRequest
# Alternate name: CertificateSigningRequest if name conflict.
class CertificateRequest:
    """
    Handler for creating x509 Certificate Signing Requests. (rw)

    Wraps the process of building and signing a CSR based on an
    identity subject and a specific extension policy.
    """

    def __init__(self, subject: x509.Name, policy: BasePolicy):
        """
        Initialize with subject identity and extension policy. (rw)

        :param subject: Identity information for the request.
        :param policy: Policy defining the required extensions.
        """
        self._subject = subject
        self._policy = policy
        self._csr = None

    def verify_input_arguments(
        self, keep:bool = False, **extentions
    ) -> x509.CertificateSigningRequestBuilder | None:
        """
        Verify input arguments and optionally prepare a CSR builder.

        This method processes extensions based on the internal policy.
        If the 'keep' argument is True, it returns a configured
        CertificateSigningRequestBuilder.

        :param kwargs: Arguments for extension processing. Use 'keep=True' to
                       receive the builder.
        :return: A configured builder if 'keep' is True, otherwise None.
        """
        # keep = extentions.pop("keep", None)
        # keep = keep if isinstance(keep, bool) and keep else False
        builder = x509.CertificateSigningRequestBuilder().subject_name(self._subject)

        for ext, critical in self._policy.get_extensions(**extentions):
            builder = builder.add_extension(ext, critical=critical)

        if keep:
            return builder
        else:
            del builder
            return None

    def build(self, private_key, **kwargs) -> Self:
        """
        Build and sign the CSR.

        Processes extensions from the policy, automatically adds the
        SubjectKeyIdentifier, and signs the request using the provided
        private key and SHA512.

        :param private_key: Key used to sign the request.
        :param kwargs: Additional arguments passed to the policy extensions.
        :raises cryptography.exceptions.UnsupportedAlgorithm: If SHA512 is
                not supported.
        :return: The instance of the class (Self).
        """
        builder = self.verify_input_arguments(keep=True, **kwargs)
        ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        builder = builder.add_extension(ski, critical=False) if builder else None
        self._csr = builder.sign(private_key, hashes.SHA512()) if builder else None
        return self

    def get_pem(self) -> bytes:
        """
        Serialize the CSR to PEM format. (ro)

        :param csr: The request object to serialize.
        :returns: PEM encoded bytes.
        """
        return self._csr.public_bytes(serialization.Encoding.PEM) if self._csr else b""

    def __repr__(self) -> str:
        """
        Return the canonical string representation. (rw)

        :returns: String containing the class name and subject.
        """
        return f"{self.__class__.__name__}(subject=<Name({self._subject.rfc4514_string()})>)"

# !CLASS - CertificateRequest



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
    test_file = testfiles_dir / "get_started_cert_request.rst"
    
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
