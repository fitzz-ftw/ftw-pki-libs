# File: src/ftwpki/baselibs/protocols.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
PKI Structural Protocols
========================

This module defines the structural interfaces (Protocols) used for
type hinting and static analysis across the PKI system. It establishes
the required data shapes for identity objects, signing policies, and
import configurations. (ro)

Main Features:
    * Definition of Distinguished Name (DN) and CSR data structures.
    * Specification of policy enforcement types and interfaces.
    * Protocols for certificate signing and multi-policy operations.
    * Requirements for certificate and intermediate CA import objects.

These protocols ensure type safety and consistency throughout the
cryptographic workflows.
"""

from pathlib import Path
from typing import Literal, Protocol


# CLASS - DistinguishedNameProtocol
class DistinguishedNameProtocol(Protocol):
    """
    Structural interface for Distinguished Name (DN) data objects. (ro)

    This protocol defines the required attributes for objects representing
    an X.509 Distinguished Name. It is used for static type checking
    to ensure that configuration or identity objects provide all
    necessary naming fields.
    """

    countryName: str
    """Two-letter ISO country code."""
    dnsubject: dict[str, str]
    """Dictionary for additional subject attributes."""
    commonName: str
    """The primary identifier (e.g., person or server name)."""
    organizationalUnitName: str
    """The department or subunit name."""
    organizationName: str
    """The legal name of the organization."""
    localityName: str
    """The city or town name."""
    stateOrProvinceName: str
    """The state, province, or region name."""


# !CLASS - DistinguishedNameProtocol


# CLASS - CSRProtocol
class CSRProtocol(DistinguishedNameProtocol):
    """
    Structural interface for Certificate Signing Request (CSR) data. (ro)

    This protocol extends the DistinguishedNameProtocol by adding fields
    required for key management and storage paths. It is used to ensure
    that objects containing identity and cryptographic material follow
    a consistent structure.
    """

    public_key: str
    """The filename or path of the public key."""
    private_key: str
    """The filename or path of the private key."""
    privatdir: str
    """The directory where sensitive key material is stored."""


# CLASS - CSRProtocol

ClientTypeName = Literal["server", "client", "clsrvr", "client-server"]
"""
Type alias for the allowed roles in a certificate request.

Supported values:
    * 'server': For server authentication.
    * 'client': For client authentication.
    * 'clsrvr' or 'client-server': For both authentication types.
"""


# CLASS - ServerClientCSR
class ServerClientCSRProtocol(CSRProtocol):
    """
    Structural interface for server and client CSR data. (ro)

    This protocol ensures that objects used for CSR generation
    provide the necessary identity and network information
    along with optional credentials.
    """

    email: str
    """The email address for the certificate subject."""

    ip_addresses: list[str]
    """A list of IP addresses for the Subject Alternative Name (SAN)."""

    host_names: list[str]
    """A list of hostnames or FQDNs for the Subject Alternative Name (SAN)."""

    password: str | None
    """The optional password used for the private key or signing."""


# !CLASS - ServerClientCSR

PolicyType = Literal["match", "optional", "supplied", "no"]
"""
Type alias for certificate policy constraints. (ro)

This type defines the allowed string values for policy enforcement 
during certificate signing. 

Supported values:
    * "match": The attribute must match the CA certificate.
    * "optional": The attribute may be present or absent.
    * "supplied": The attribute must be present in the request.
    * "no": The attribute must not be present.
"""


# CLASS - PolicyProtocol
class PolicyProtocol(Protocol):
    """
    Structural interface for certificate policy definitions. (ro)

    This protocol defines the required attributes for objects that specify
    how Distinguished Name fields and general policies should be enforced
    during certificate issuance. It ensures that policy objects provide
    consistent enforcement rules.
    """

    policy_name: str
    """The unique identifier of the policy."""
    countryName: PolicyType
    """Enforcement rule for the country field."""
    stateOrProvinceName: PolicyType
    """Enforcement rule for the state field."""
    localityName: PolicyType
    """Enforcement rule for the city field."""
    organizationName: PolicyType
    """Enforcement rule for the organization field."""
    organizationalUnitName: PolicyType
    """Enforcement rule for the unit field."""
    commonName: PolicyType
    """Enforcement rule for the common name field."""
    policy: dict[str, PolicyType]
    """A mapping of additional policy constraints."""


# !CLASS - PolicyProtocol


# CLASS - SigningProtocol
class SigningProtocol(PolicyProtocol):
    """
    Structural interface for certificate signing operations. (ro)

    This protocol extends the PolicyProtocol by adding cryptographic
    material and configuration settings required for the signing process.
    It ensures that objects used for issuing certificates provide all
    necessary paths, keys, and validity constraints.
    """

    private_key: str
    """The filename or path of the CA private key."""
    private_dir: str
    """The directory where the private key is located."""
    certificate: str
    """The filename or path of the issuer certificate."""
    certificat_sign_request: str
    """The path to the CSR to be signed."""
    path_length: int
    """The maximum number of non-self-issued intermediate certificates that may follow."""
    validity_days: int
    """The number of days the new certificate will be valid."""


# !CLASS - SigningProtocol


# CLASS - SignParserProtocol
class SignParserProtocol(SigningProtocol):
    """
    Structural interface for signing operations with passphrase files. (ro)

    This protocol extends the SigningProtocol by adding a requirement
    for a passphrase file path. It is used to ensure that objects
    intended for automated signing processes provide the location of
    the required security credentials.
    """

    passphrasefile: str
    """The filename or path to the file containing
                              the private key password."""


# !CLASS - SignParserProtocol


# CLASS - MultiSignParserProtocol
class MultiSignParserProtocol(SignParserProtocol):
    """
    Structural interface for multi-policy signing operations. (ro)

    This protocol extends the SignParserProtocol by adding a policy type
    field. It is used to ensure that objects for complex signing
    processes provide both the necessary security credentials and a
    specific policy identifier.
    """

    policy_type: str
    """The identifier or category of the policy to
                           be applied during the signing process."""


# !CLASS - MultiSignParserProtocol


# CLASS - CertImportProtocol
class CertImportProtocol(Protocol):
    """
    Structural interface for certificate import operations. (ro)

    This protocol defines the required attributes for objects used to
    import certificate material. It ensures that the necessary paths
    for the private key and the encrypted archive are provided for
    processing.
    """

    private_keyfile: str
    """The filename or path to the private key
                               associated with the import."""
    enc_zipfile: str
    """The filename or path to the encrypted ZIP
                           archive containing the certificate data."""


# !CLASS - CertImportProtocol


# CLASS - IntermedImportProtocol
class IntermedImportProtocol(Protocol):
    """
    Structural interface for intermediate certificate import operations. (ro)

    This protocol defines the required attributes for objects used to
    import intermediate CA material. It ensures that paths for security
    credentials and policy definitions are provided for the import process.
    """

    passphrase_file: str
    """The filename or path to the file containing the private key password."""
    policies: str
    """The path to the configuration file containing policy definitions."""
    policy: str
    """The specific name of the policy to be applied."""


# !CLASS - IntermedImportProtocol

PathCategoryType = Literal[
    "private_keys",
    "certs",
    "public_data",
    "chains",
    "passphrases",
    "policies",
]


# SECTION - Base Configuration
# CLASS - ConfigPathesProtocol
class ConfigPathesProtocol(Protocol):
    """
    Structural interface for configuration path objects. (ro)

    This protocol defines the required attributes for objects that provide
    access to the various directory paths used in the PKI system. It is
    used to ensure that configuration objects provide consistent and
    accessible path information for key storage, requests, and certificates.
    """

    private_keys: str
    """The directory path where private keys are stored."""
    certs: str
    """The directory path where issued certificates are stored."""
    public_data: str
    """The directory path for public data storage."""
    chains: str
    """The directory path where certificate chains are stored."""

    def __getitem__(key: str) -> str: ...


# !CLASS - ConfigPathesProtocol

# CLASS - ConfigExtentionsProtocol


class ConfigExtentionsProtocol(Protocol):
    """
    Structural interface for configuration file extension attributes. (ro)

    This protocol defines the required attributes for objects that specify
    the file extensions used for different types of certificate-related
    files. It ensures that configuration objects provide consistent
    information about the expected file formats for certificates, public
    keys, chains, and related configurations.
    """

    ext_cert: str
    """The file extension for certificate files."""
    ext_public: str
    """The file extension for public key files."""
    ext_signedcert: str
    """The file extension for signed certificate archives."""


# !CLASS - ConfigExtentionsProtocol


# CLASS - FullConfigProtocol
class FullConfigProtocol(ConfigPathesProtocol, ConfigExtentionsProtocol):
    def __getitem__(key: str) -> str: ...

    pass


# !CLASS - FullConfigProtocol


# CLASS - PathConfigPathesProtocol
class PathConfigPathesProtocol(Protocol):
    """
    Structural interface for configuration path objects with Path types. (ro)

    This protocol defines the required attributes for objects that provide
    access to the various directory paths used in the PKI system, but with
    Path objects instead of strings. It is used to ensure that configuration
    objects provide consistent and accessible path information for key storage,
    requests, and certificates in a more type-safe manner.
    """

    private_keys: Path
    """The directory path where private keys are stored."""
    public_data: Path
    """The directory path for public data storage."""
    certs: Path
    """The directory path where issued certificates are stored."""
    chains: Path
    """The directory path where certificate chains are stored."""


# !CLASS - PathConfigPathesProtocol

# !SECTION - Base Configuration


# SECTION - User Configuration
# DOC - Docstring
class UserConfigPathesProtocol(ConfigPathesProtocol):
    pass


# DOC - Docstring
class UserConfigExtentionsProtocol(ConfigExtentionsProtocol):
    pass


# DOC - Docstring
class UserFullConfigProtocol(UserConfigPathesProtocol, UserConfigExtentionsProtocol):
    pass


# DOC - Docstring
class UserPathConfigPathesProtocol(PathConfigPathesProtocol):
    pass


#!SECTION - User Configuration


# SECTION - Rootsigner Configuration
# DOC - Docstring
class RootSignConfigPathesProtocol(ConfigPathesProtocol):
    # DOC - Docstring
    passphrases: str


# DOC - Docstring
class RootSignConfigExtentionsProtocol(ConfigExtentionsProtocol):
    # DOC - Docstring
    ext_chain: str


# DOC - Docstring
class RootSignPathConfigPathesProtocol(PathConfigPathesProtocol):
    # DOC - Docstring
    passphrases: Path


# !SECTION - Rootsigner Configuration


# SECTION - Leaf Configuration
# DOC - Docstring
class LeafConfigPathesProtocol(ConfigPathesProtocol):
    pass


# DOC - Docstring
class LeafConfigExtentionsProtocol(ConfigExtentionsProtocol):
    pass


# DOC - Docstring
class LeafFullConfigProtocol(LeafConfigPathesProtocol, LeafConfigExtentionsProtocol):
    pass


# DOC - Docstring
class LeafPathConfigPathesProtocol(PathConfigPathesProtocol):
    pass


# !SECTION - Leaf Configuration


# SECTION - Intermediate Configuration
# DOC - Docstring
class IntermedConfigPathesProtocol(RootSignConfigPathesProtocol):
    # DOC - Docstring
    policies: str


# DOC - Docstring
class IntermedConfigExtentionsProtocol(RootSignConfigExtentionsProtocol):
    # DOC - Docstring
    ext_policiy: str


# DOC - Docstring
class IntermedFullConfigProtocol(IntermedConfigPathesProtocol, IntermedConfigExtentionsProtocol):
    pass


# DOC - Docstring
class IntermedPathConfigPathesProtocol(RootSignPathConfigPathesProtocol):
    # DOC - Docstring
    policies: Path


# !SECTION - Intermediate Configuration


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
    test_file = testfiles_dir / "get_started_protocols.rst"

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
