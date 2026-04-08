# File: src/ftwpki/baselibs/policies.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2.1
"""
policies
===============================


Modul policies documentation
"""

from abc import ABC, abstractmethod
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


class BasePolicy(ABC):
    def __init__(self, **kwargs):
        super().__init__()

    @abstractmethod
    def get_extensions(self, **kwargs) -> list[tuple[x509.ExtensionType, bool]]:
        """Returns a list of (extension, critical) tuples."""
        

class RootPolicy(BasePolicy):
    """
    Policy for Root CA Certificates.
    Matches 'v3_ca_cert' from openssl.cnf.
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        # Root CAs haben meist keine path_length Einschränkung (None)
        # Das entspricht 'basicConstraints = critical, CA:true' ohne pathlen
        self._basic_constraints = x509.BasicConstraints(ca=True, path_length=None)

        self._key_usage = x509.KeyUsage(
            digital_signature=False,  # Root CAs signieren meist keine Daten direkt
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,  # Wichtig: Darf Zertifikate signieren
            crl_sign=True,  # Wichtig: Darf CRLs signieren
            encipher_only=False,
            decipher_only=False,
        )

    def get_extensions(self, **kwargs) -> list[tuple[x509.ExtensionType, bool]]:
        # Eine Root-CA braucht normalerweise keine SANs (alt_names),
        # da sie nur über ihren Distinguished Name (DN) identifiziert wird.
        return [(self._basic_constraints, True), (self._key_usage, True)]

class IntermediatePolicy(BasePolicy):
    def __init__(self,**kwargs):
        path_length = kwargs.pop("path_length", 0)
        super().__init__(**kwargs)
        self._basic_constraints = x509.BasicConstraints(ca=True, path_length=path_length)
        self._key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )
    def get_extensions(self, **kwargs) -> list[tuple[x509.ExtensionType, bool]]:
        
        return [
            (self._basic_constraints, True),
            (self._key_usage, True)
        ]

class UserPolicy(BasePolicy):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._basic_constraints = x509.BasicConstraints(ca=False, path_length=None)
        self._key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,  # nonRepudiation
            key_encipherment=True,
            data_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        self._extended_key_usage = x509.ExtendedKeyUsage(
            [
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.EMAIL_PROTECTION,
                ExtendedKeyUsageOID.CODE_SIGNING,
            ]
        )

    def get_extensions(self, **kwargs) -> list[tuple[x509.ExtensionType, bool]]:
        extensions = [
            (self._basic_constraints, True),
            (self._key_usage, True),
            (self._extended_key_usage, False),
        ]

        alt_names = kwargs.get("alt_names", [])
        if alt_names:
            # Bei Usern oft RFC822Name (E-Mail) statt DNSName
            names = [
                x509.RFC822Name(str(n)) if "@" in str(n) else x509.DNSName(str(n))
                for n in alt_names
            ]
            extensions.append((x509.SubjectAlternativeName(names), False))

        return extensions

class ServerPolicy(BasePolicy):
    """
    Policy for SSL/TLS Server Certificates.
    Matches 'v3_server_cert' from your openssl.cnf.
    """
    def __init__(self,**kwargs) -> None:
        super().__init__(**kwargs)
        self._basic_constraints = x509.BasicConstraints(ca=False, path_length=None)
        self._key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        self._extended_key_usage = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])

    def get_extensions(self, **kwargs) -> list[tuple[x509.ExtensionType, bool]]:
        """
        Build extensions for a server certificate.
        Expects 'alt_names' as a list of strings in kwargs.
        """

        extensions = [(self._basic_constraints, True), 
                      (self._key_usage, True), 
                      (self._extended_key_usage, False)]

        # 4. Subject Alternative Name (SAN) - Die 'alt_names' Logik
        # Wir ziehen die Namen aus den kwargs, falls vorhanden
        alt_names = kwargs.get("alt_names", [])
        if alt_names:
            dns_names = [x509.DNSName(name) for name in alt_names]
            san = x509.SubjectAlternativeName(dns_names)
            extensions.append((san, False))

        return extensions

class ClientPolicy(BasePolicy):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._basic_constraints = x509.BasicConstraints(ca=False, path_length=None)
        self._key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        self._extended_key_usage = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])

    def get_extensions(self, **kwargs) -> list[tuple[x509.ExtensionType, bool]]:
        extensions = [
            (self._basic_constraints, True),
            (self._key_usage, True),
            (self._extended_key_usage, False),
        ]

        alt_names = kwargs.get("alt_names", [])
        if alt_names:
            dns_names = [x509.DNSName(str(name)) for name in alt_names]
            extensions.append((x509.SubjectAlternativeName(dns_names), False))

        return extensions

class StandalonePolicy(BasePolicy):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._basic_constraints = x509.BasicConstraints(ca=False, path_length=None)
        self._key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        # Kombination aus beidem
        self._extended_key_usage = x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
        )

    def get_extensions(self, **kwargs) -> list[tuple[x509.ExtensionType, bool]]:
        extensions = [
            (self._basic_constraints, True),
            (self._key_usage, True),
            (self._extended_key_usage, False),
        ]

        alt_names = kwargs.get("alt_names", [])
        if alt_names:
            dns_names = [x509.DNSName(str(name)) for name in alt_names]
            extensions.append((x509.SubjectAlternativeName(dns_names), False))

        return extensions

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
    test_file = testfiles_dir / "get_started_policies.rst"
    
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
