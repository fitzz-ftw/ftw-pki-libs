# File: src/ftwpki/baselibs/request.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2.1
"""
request
===============================


Modul request documentation
"""

from pathlib import Path
from typing import Self

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from ftwpki.baselibs.policies import BasePolicy


class CertificateRequest:
    """
    Handler for creating x509 Certificate Signing Requests.
    """

    def __init__(self, subject: x509.Name, policy: BasePolicy):
        """
        Initialize with subject identity and extension policy.

        :param subject: Identity information for the request.
        :param policy: Policy defining the required extensions.
        """
        self._subject = subject
        self._policy = policy
        self._csr=None

    def build(self, private_key, **kwargs) ->Self:
        """
        Build and sign the CSR.

        :param private_key: Key used to sign the request.
        :raises cryptography.exceptions.UnsupportedAlgorithm: If the hash algorithm is not 
                supported.
        """
        builder = x509.CertificateSigningRequestBuilder().subject_name(self._subject)

        for ext, critical in self._policy.get_extensions(**kwargs):
            builder = builder.add_extension(ext, critical=critical)

        ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        builder = builder.add_extension(ski, critical=False)

        self._csr = builder.sign(private_key, hashes.SHA512())
        return self

    def get_pem(self) -> bytes:
        """
        Serialize the CSR to PEM format.

        :param csr: The request object to serialize.
        :returns: PEM encoded bytes.
        """
        return self._csr.public_bytes(serialization.Encoding.PEM) if self._csr else b""

    def __repr__(self) -> str:
        """
        Return the canonical string representation.

        :returns: String containing the class name and subject.
        """
        return f"{self.__class__.__name__}(subject=<Name({self._subject.rfc4514_string()})>)"




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
    test_file = testfiles_dir / "get_started_request.rst"
    
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
