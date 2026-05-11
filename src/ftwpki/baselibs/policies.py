# File: src/ftwpki/baselibs/policies.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2.1
"""
X.509 Certificate Issuance Policies
===================================

This module defines the structural policies for different certificate types
within the PKI. It translates high-level policy names into specific X.509
extensions, key usages, and constraints compliant with RFC 5280. (rw)

Main Features:
    * Base abstract class for policy definition.
    * Specific policies for CAs (Root/Intermediate) and End-Entities.
    * Support for Subject Alternative Names (SAN) via dynamic kwargs.
"""

import ipaddress
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


class BasePolicy(ABC):
    """
    Abstract base class for all certificate policies. (rw)

    Provides the foundational interface for defining X.509 extensions.
    Specific certificate types (Root, Server, User, etc.) must implement
    this interface to ensure consistent extension handling.
    """

    def __init__(self, **kwargs):
        """
        Initialize the base policy. (rw)

        :param kwargs: Optional parameters for child policy configuration.
        """
        super().__init__()

    @abstractmethod
    def get_extensions(self, **kwargs) -> list[tuple[x509.ExtensionType, bool]]:
        """
        Return a list of (extension, critical) tuples. (ro)

        This is an abstract method that must be implemented by subclasses
        to define specific X.509 extensions.

        :param kwargs: Optional parameters for extension generation.
        :returns: List of tuples containing the extension and its criticality.
        """

    def get_san_entries(self, **kwargs) -> list[Any]:
        """
        Build a list of GeneralName objects for SAN extensions. (rw)

        Supported keys in kwargs:
        - dns_names: List of DNS strings
        - ip_addresses: List of IP strings (v4/v6)
        - emails: List of RFC822 email strings
        - uris: List of URI strings
        - oids: List of x509.ObjectIdentifier objects
        - directory_names: List of x509.Name objects
        """
        san_entries = []

        # 1. DNS Namen (alt_names)
        for name in kwargs.get("dns_names", []):
            if "." not in name and name.lower() != "localhost":
                raise ValueError(f"Hostname '{name}' is not a FQDN (missing dot).")
            san_entries.append(x509.DNSName(name))

        # 2. IP Adressen (alt_ips) - Trennung spart die Exception
        for ip_str in kwargs.get("ip_addresses", []):
            # Hier nutzen wir ipaddress nur noch zur Typ-Konvertierung, 
            # im Vertrauen darauf, dass der Caller valide IPs liefert.
            san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str)))
        
        # 3. E-Mail-Adressen (S/MIME / User-Identifikation)
        for email in kwargs.get("emails", []):
            san_entries.append(x509.RFC822Name(email))

        # 4. URIs (Service Mesh / SPIFFE / Web-Ressourcen)
        for uri in kwargs.get("uris", []):
            san_entries.append(x509.UniformResourceIdentifier(uri))

        # 5. Registered IDs (Spezielle OIDs für IoT oder Behörden)
        # Erwartet Instanzen von cryptography.x509.ObjectIdentifier
        for oid in kwargs.get("oids", []):
            san_entries.append(x509.RegisteredID(oid))

        for dirname in kwargs.get("directory_names", []):
            san_entries.append(x509.DirectoryName(dirname))

        return san_entries


    def __repr__(self) -> str:
        """
        Return a formal representation of the policy. (rw)

        :returns: The class name as a string.
        """
        return f"{self.__class__.__name__}()"


class RootPolicy(BasePolicy):
    """
    Policy for Root CA Certificates. (rw)

    This policy is used for self-signed trust anchors. It defines the
    foundational extensions required for the top-level authority in a
    certificate hierarchy.
    """

    def __init__(self, **kwargs) -> None:
        """
        Initialize the root CA policy. (rw)

        Sets up BasicConstraints (CA:True, no path limit) and KeyUsage
        (Cert/CRL Sign).
        """
        super().__init__(**kwargs)
        self._basic_constraints = x509.BasicConstraints(ca=True, path_length=None)

        self._key_usage = x509.KeyUsage(
            digital_signature=False,
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
        """
        Assemble extensions for a root CA. (ro)

        :returns: A list of configured X.509 extensions.
        """
        return [(self._basic_constraints, True), (self._key_usage, True)]


class IntermediatePolicy(BasePolicy):
    """
    Policy for Intermediate CA Certificates. (rw)

    This policy inherits directly from BasePolicy and is used to issue
    subordinate CA certificates. It allows defining a path length
    constraint to limit the depth of the subsequent CA hierarchy.
    """

    def __init__(self, **kwargs):
        """
        Initialize the intermediate policy. (rw)

        Extracts 'path_length' from kwargs (defaulting to 0) before
        initializing BasicConstraints (CA:True) and KeyUsage
        (Digital Signature, Cert/CRL Sign).

        :param kwargs: Supports 'path_length' (int).
        """
        self._path_length = kwargs.pop("path_length", 0)
        super().__init__(**kwargs)
        self._basic_constraints = x509.BasicConstraints(ca=True, path_length=self._path_length)
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
        """
        Assemble extensions for an intermediate CA. (ro)

        :returns: A list containing BasicConstraints and KeyUsage extensions.
        """

        return [(self._basic_constraints, True), (self._key_usage, True)]

    def __repr__(self) -> str:
        """
        Return a formal representation of the intermediate policy. (rw)

        :returns: String containing the class name and the path_length value.
        """
        return f"{self.__class__.__name__}(path_length: {self._path_length})"


class UserPolicy(BasePolicy):
    """
    Policy for User and End-Entity Certificates. (rw)

    Inherits directly from BasePolicy. This policy is designed for personal
    certificates, providing support for client authentication, secure email
    (S/MIME), and code signing.
    """

    def __init__(self, **kwargs) -> None:
        """
        Initialize the user policy. (rw)

        Sets up BasicConstraints (CA:False), extensive KeyUsage (including
        nonRepudiation and Data Encipherment), and ExtendedKeyUsage
        (Client Auth, Email Protection, Code Signing).
        """
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
        """
        Assemble X.509 extensions for a user certificate.

        This method collects standard certificate extensions and adds 
        Subject Alternative Names (SAN) based on the provided entries 
        in the arguments. For a full list of supported SAN entries, 
        see: :meth:`BasePolicy.get_san_entries`.

        :param kwargs: Keyword arguments containing the pre-processed SAN entries.
        :raises Exception: If the extension assembly fails.
        :returns: A list of tuples containing the extension and its criticality flag.
        """
        extensions = [
            (self._basic_constraints, True),
            (self._key_usage, True),
            (self._extended_key_usage, False),
        ]

        san_entries = self.get_san_entries(**kwargs)
        if san_entries:
            san = x509.SubjectAlternativeName(san_entries)
            extensions.append((san, False))

        return extensions


class ServerPolicy(BasePolicy):
    """
    Policy for SSL/TLS Server Certificates. (rw)

    Matches 'v3_server_cert' from standard OpenSSL configurations. This
    policy is intended for end-entity certificates used to identify
    servers in secure communication.
    """

    def __init__(self, **kwargs) -> None:
        """
        Initialize the server policy. (rw)

        Sets up BasicConstraints (CA:False), KeyUsage (Digital Signature,
        Key Encipherment), and ExtendedKeyUsage (Server Auth).
        """
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
        Build X.509 extensions for a server certificate **(ro)**.

        This method assembles a list of extensions required for server 
        authentication. It includes basic constraints, key usage, and 
        extended key usage, as well as Subject Alternative Names (SAN) 
        if network identities are provided. For a full list of supported SAN entries, 
        see: :meth:`BasePolicy.get_san_entries`.

        :param kwargs: Keyword arguments that can include data for SAN generation.
        :raises Exception: If the extension assembly or SAN generation fails.
        :returns: A list of tuples containing the extension objects and their criticality.
        """

        extensions = [
            (self._basic_constraints, True),
            (self._key_usage, True),
            (self._extended_key_usage, False),
        ]

        san_entries = self.get_san_entries(**kwargs)
        if san_entries:
            san = x509.SubjectAlternativeName(san_entries)
            extensions.append((san, False))


        return extensions


class ClientPolicy(BasePolicy):
    """
    Independent policy for generic Client Certificates. (rw)

    This policy inherits directly from BasePolicy and is specifically
    tailored for client authentication. It maintains strict separation
    from server or user-specific logic to ensure maximum flexibility.
    """

    def __init__(self, **kwargs) -> None:
        """
        Initialize the client policy. (rw)

        Sets up BasicConstraints (CA:False), KeyUsage (Digital Signature,
        Key Encipherment), and ExtendedKeyUsage (Client Auth only).
        """
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
        """
        Assemble the X.509 extensions for a client certificate **(ro)**.

        This method combines basic constraints, key usage, and extended 
        key usage. It also adds Subject Alternative Names (SAN) if 
        network identities are provided in the arguments. 
        For a full list of supported SAN entries, see: :meth:`BasePolicy.get_san_entries`.

        :param kwargs: Arbitrary keyword arguments, may contain 'alt_names'.
        :raises Exception: If the SAN entry generation fails.
        :returns: A list of tuples containing the extension type and its critical flag.
        """
        extensions = [
            (self._basic_constraints, True),
            (self._key_usage, True),
            (self._extended_key_usage, False),
        ]

        san_entries = self.get_san_entries(**kwargs)
        if san_entries:
            san = x509.SubjectAlternativeName(san_entries)
            extensions.append((san, False))


        return extensions


class ClientServerPolicy(BasePolicy):
    """
    Independent policy for special purpose certificates. (rw)

    This policy inherits directly from BasePolicy. it is designed for
    certificates that require a specific combination of server and
    client authentication without being tied to the standard
    Server/User hierarchy.
    """

    def __init__(self, **kwargs) -> None:
        """
        Initialize the standalone policy. (rw)

        Sets up BasicConstraints (CA:False), KeyUsage (Digital Signature,
        Key Encipherment), and ExtendedKeyUsage (Server & Client Auth).
        """
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
        """
        Assemble X.509 extensions for a standalone certificate.

        This method prepares a list of certificate extensions, including 
        standard constraints and usage rules. It also includes Subject 
        Alternative Names (SAN) if network identity data is provided.
        For a full list of supported SAN entries, see: :meth:`BasePolicy.get_san_entries`.

        :param kwargs: Keyword arguments that can include 'alt_names' for SAN generation.
        :raises Exception: If generating Subject Alternative Names fails.
        :returns: A list of tuples where each contains an extension and its criticality flag.
        """
        extensions = [
            (self._basic_constraints, True),
            (self._key_usage, True),
            (self._extended_key_usage, False),
        ]

        san_entries = self.get_san_entries(**kwargs)
        if san_entries:
            san = x509.SubjectAlternativeName(san_entries)
            extensions.append((san, False))

        return extensions


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
