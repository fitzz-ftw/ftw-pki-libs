# File: src/ftwpki/baselibs/cli_parser.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
CLI Argument Parsing Utilities
==============================

This module provides specialized ArgumentParser subclasses for PKI
operations. It handles the extraction of Distinguished Name (DN)
attributes, certificate signing policies, and import configurations from
command-line arguments. (rw)

Main Features:
    * Custom actions for OpenSSL-style subject strings.
    * Robust parsing for DN, CSR, and signing parameters.
    * Version-specific fixes for argparse behavior (Python 3.11).
    * Integration with structural protocols for type safety.
"""

import sys
from argparse import (
    Action,
    ArgumentError,
    ArgumentParser,
    Namespace,
)
from pathlib import Path
from typing import cast

from ftwpki.baselibs.protocols import (
    CertImportProtocol,
    ClientTypeName,
    CSRProtocol,
    DistinguishedNameProtocol,
    IntermedImportProtocol,
    MultiSignParserProtocol,
    PolicyProtocol,
    ServerClientCSRProtocol,
    SignParserProtocol,
)

ALIAS_MAP = {
    "C": "countryName",
    "ST": "stateOrProvinceName",
    "O": "organizationName",
    "CN": "commonName",
    "L": "localityName",
    "OU": "organizationalUnitName",
}
"""
Mapping of short CLI aliases to long X.509 attribute names. (ro)

This dictionary translates common OpenSSL-style abbreviations (e.g., 'CN') 
into the full identifiers used by the cryptography library and the 
DistinguishedNameProtocol. It is used during subject string parsing and 
argument synchronization.
"""
# CLASS - SubjAction


# CLASS - SubjAction
class SubjAction(Action):
    """
    Argparse Action for parsing OpenSSL-style subject strings. (rw)

    This action converts a string like '/C=DE/CN=Example' into a dictionary
    of Distinguished Name attributes, mapping short aliases to long
    attribute names.
    """

    @staticmethod
    def _parse_subj_string(subj_str: str) -> dict[str, str]:
        """
        Parse a subject string into a normalized dictionary. (rw)

        :param subj_str: The raw subject string (e.g., from -subj).
        :raises ValueError: If a fragment does not follow the 'Key=Value' format.
        :returns: A dictionary of DN attributes.
        """
        # Trenne bei / oder , und filtere leere Fragmente
        parts = [p.strip() for p in subj_str.replace(",", "/").split("/") if p.strip()]
        subj_dict = {}
        for part in parts:
            if "=" not in part:
                raise ValueError(
                    f"Fragment '{part}' does not contain '=' (Expected format: Key=Value)"
                )

            key, value = part.split("=", 1)
            key = key.strip()
            long_name = ALIAS_MAP.get(key, key)
            subj_dict[long_name] = value.strip()

        return subj_dict

    def __call__(self, parser:ArgumentParser, 
                 namespace:Namespace, 
                 values:str, 
                 option_string:str|None=None):
        """
        Execute the action during argument parsing. (rw)

        :raises ArgumentError: If the subject string format is invalid.
        """
        try:
            subj_dict = self._parse_subj_string(values)
            setattr(namespace, self.dest, subj_dict)
        except Exception as e:
            raise ArgumentError(self, f"Ungültiges Subj-Format: {e}")
# !CLASS - SubjAction


# CLASS - ArgparseFix311
class ArgparseFix311(ArgumentParser):
    """
    Custom ArgumentParser to fix Python 3.11 specific behaviors. (rw)

    Ensures that errors consistently raise ArgumentError instead of
    exiting the process, which is critical for library usage and testing.
    """

    def error(self, message):
        """
        Handle parsing errors by raising ArgumentError. (rw)

        :param message: The error message to report.
        :raises ArgumentError: Always raises to prevent SystemExit.
        """
        if sys.version_info[:2] == (3, 11): # py 3.11 only no cover
            raise ArgumentError(None, message)
        super().error(message) # not py 3.11 no·‌cover

    def exit(self, status=0, message=None):
        """
        Intercept exit calls to maintain control flow. (rw)

        :param status: Exit status code.
        :param message: Optional error message.
        """
        if sys.version_info[:2] == (3, 11) and status != 0: # py 3.11 only no cover
            self.error(message or f"Exited with status {status}")
        super().exit(status, message)  # not py 3.11 no cover
# !CLASS - ArgparseFix311


# CLASS - DistinguishedNameParser
class DistinguishedNameParser(ArgparseFix311):
    """
    Parser for X.509 Distinguished Name attributes. (rw)

    This class handles individual DN flags (like -CN, -O) as well as
    combined subject strings (-subj) and TOML configuration files.
    """

    def __init__(
        self,
        prog: str | None = None,
        usage: str | None = None,
        description: str | None = None,
        epilog: str | None = None,
        exit_on_error: bool = False,
        **kwargs,
    ) -> None:
        """Initialize the DN parser with default PKI arguments. (rw)"""
        super().__init__(prog, usage, description, epilog, exit_on_error=exit_on_error, **kwargs)
        self._setup_parser()

    def _setup_parser(self) -> None:
        """Configure the available CLI arguments for DN attributes. (rw)"""
        self.add_argument(
            "-C", "--countryName", dest="countryName", default="", help="Land (2 Buchstaben)"
        )
        self.add_argument(
            "-ST",
            "--stateOrProvinceName",
            dest="stateOrProvinceName",
            default="",
            help="Bundesland/Provinz",
        )
        self.add_argument("-L", "--localityName", dest="localityName", default="", help="Stadt/Ort")
        self.add_argument(
            "-O",
            "--organizationName",
            dest="organizationName",
            default="",
            help="Organisation/Firma",
        )
        self.add_argument(
            "-OU",
            "--organizationalUnitName",
            dest="organizationalUnitName",
            default="",
            help="Abteilung/OU",
        )
        self.add_argument(
            "-CN",
            "--commonName",
            dest="commonName",
            default="",
            help="Vollqualifizierter Domainname (FQDN)",
        )
        conf_group = self.add_mutually_exclusive_group()
        conf_group.add_argument(
            "-subj",
            dest="dnsubject",
            default="",
            action=SubjAction,
            help="DN im OpenSSL-Format, z.B. /C=DE/O=Firma/CN=Server",
        )
        conf_group.add_argument(
            "--conf_file",
            dest="conf_file",
            type=Path,
            help="Path to a TOML-Configfile",
        )

    def sync_arguments(self, parsed_args: DistinguishedNameProtocol) -> DistinguishedNameProtocol:
        """
        Synchronize individual DN flags with the dnsubject dictionary. (rw)

        :param parsed_args: The namespace object containing parsed attributes.
        :returns: The updated protocol-compliant object.
        """
        final_dn = getattr(parsed_args, "dnsubject", {}) or {}
        for arg in ALIAS_MAP.values():
            arg_v = getattr(parsed_args, arg, "")
            if arg_v:
                final_dn[arg] = arg_v
            else:
                dn_arg = final_dn.get(arg, "")
                if dn_arg:
                    setattr(parsed_args, arg, final_dn[arg])
        parsed_args.dnsubject = final_dn
        return parsed_args

    def parse_args(
        self, args: list[str] | None = None, namespace: Namespace | None = None
    ) -> DistinguishedNameProtocol:
        """
        Parse CLI arguments and return a synchronized DN protocol object. (rw)

        :param args: List of argument strings.
        :param namespace: Existing namespace to populate.
        :returns: An object following the DistinguishedNameProtocol.
        """
        arg_parsed = cast(
            DistinguishedNameProtocol, super().parse_args(args=args, namespace=namespace)
        )
        return self.sync_arguments(arg_parsed)
# !CLASS - DistinguishedNameParser


def get_dn_parser() -> DistinguishedNameParser:
    """
    Factory function to create a DistinguishedNameParser instance.

    :returns: A new instance of the Distinguished Name parser.
    """
    return DistinguishedNameParser()

# CLASS - CSRParser
class CSRParser(DistinguishedNameParser):
    """
    Parser for Certificate Signing Request (CSR) parameters. (rw)

    Extends DN parsing with arguments for key management and storage paths.
    """

    def _setup_parser(self) -> None:
        """Configure additional arguments for CSR key paths. (rw)"""
        super()._setup_parser()
        self.add_argument("-k", "--key", "--private-key", default="", dest="private_key")
        self.add_argument(
            "-p",
            "--pub",
            "--public-key",
            dest="public_key",
            default="",
        )
        self.add_argument("--private-dir", dest="privatdir", default="")

    def parse_args(
        self, args: list[str] | None = None, namespace: Namespace | None = None
    ) -> CSRProtocol:
        """
        Parse arguments and return a CSR protocol object. (rw)

        :returns: An object following the CSRProtocol.
        """
        return cast(CSRProtocol, super().parse_args(args, namespace))
# !CLASS - CSRParser


def get_csr_parser() -> CSRParser:
    """
    Factory function to create a CSRParser instance.

    :returns: A new instance of the Certificate Signing Request parser.
    """
    return CSRParser()

# CLASS - ServerClientCSRParser
class ServerClientCSRParser(CSRParser):
    """
    Parser for server and client certificate signing requests. (ro)

    This class extends the basic CSR parser to include network-specific 
    arguments like email, IP addresses, and hostnames.
    """
    def __init__(self, **kwargs) -> None:
        """
        Initialize the ServerClient parser.

        :param kwargs: Arbitrary keyword arguments for the parser configuration.
        :raises KeyError: If required configuration keys are missing in kwargs.
        """
        self._type_name: ClientTypeName = kwargs.pop("typename", "server")
        self._type_name = self._type_name if self._type_name else "server"
        kwargs.setdefault("exit_on_error", False)
        super().__init__(**kwargs)

    def _setup_parser(self) -> None:
        """
        Configure the argument parser with specific network fields.

        :raises argparse.ArgumentError: If an argument conflict occurs.
        """
        super()._setup_parser()
        self.add_argument("email",
                          help="Email address the signed certificate send to."
                          )
        self.add_argument("-ip", "--ip-address",
                          action="append",
                          default=[],
                          dest="ip_addresses",
                          help=f"The ip addresses of the {self._type_name}.")
        self.add_argument("-hn", "--host-name",
                          action="append",
                          default=[],
                          dest="host_names",
                          help=f"The hostnames of the {self._type_name}.")

    def parse_args(self, args: list[str] | None = None, 
                   namespace: Namespace | None = None) -> ServerClientCSRProtocol:
        """
        Parse command line arguments and validate network identity.

        :param args: List of strings to parse. Default is sys.argv.
        :param namespace: An object to take the attributes.
        :raises argparse.ArgumentError: If neither an IP address nor a hostname is provided.
        :returns: An object containing the parsed and validated CSR data.
        """
        ret = cast(ServerClientCSRProtocol,super().parse_args(args, namespace))
        if not ret.ip_addresses and not ret.host_names:
            raise ArgumentError(None,"At least an ip address or a hostname has to be given")
        return ret

#!CLASS - ServerClientCSRParser

def get_server_client_csr_parser() -> ServerClientCSRParser:
    """
    Factory function to create a ServerClientCSRParser instance.

    :returns: A new instance of the Server/Client CSR parser.
    """
    return ServerClientCSRParser() 

# CLASS - PolicyParser
class PolicyParser(ArgparseFix311):
    """
    Parser for certificate issuance policies. (rw)

    Defines how individual DN fields should be treated during signing
    (e.g., match, optional, supplied).
    """

    def __init__(self, **kwargs) -> None:
        """Initialize the policy parser. (rw)"""
        kwargs.setdefault("exit_on_error", False)
        super().__init__(**kwargs)
        self._setup_parser()

    def _setup_parser(self) -> None:
        """Configure arguments for policy constraint settings. (rw)"""
        self.fields = {
            "C": "countryName",
            "ST": "stateOrProvinceName",
            "L": "localityName",
            "O": "organizationName",
            "OU": "organizationalUnitName",
            "CN": "commonName",
        }

        choices = ["match", "optional", "supplied", "no"]

        for alias, full_name in self.fields.items():
            self.add_argument(
                f"-{alias}",
                f"--{full_name}",
                dest=full_name,
                choices=choices,
                default="no",
                help=f"Policy für {full_name} (Default: %(default)s)",
            )
        self.add_argument(
            "-p",
            "--policy-name",
            dest="policy_name",
            default=None,
            help="Name of the policy. (Default: %(default)s)",
        )
        self.add_argument(
            "--conf-file",
            dest="conf_file",
            type=Path,
            help="Path to a TOML-Configfile",
        )

    def parse_args(
        self, args: list[str] | None = None, namespace: Namespace | None = None
    ) -> PolicyProtocol:
        """
        Parse and aggregate policy constraints into a dictionary. (rw)

        :returns: An object following the PolicyProtocol.
        """
        ret_args = cast(PolicyProtocol, super().parse_args(args=args, namespace=namespace))
        ret_args.policy = {}
        for v in self.fields.values():
            ret_args.policy[v] = getattr(ret_args, v, "no")
        return cast(PolicyProtocol, ret_args)

# !CLASS - PolicyParser


def get_policy_parser() -> PolicyParser:
    """
    Factory function to create a PolicyParser instance.

    :returns: A new instance of the certificate policy parser.
    """
    return PolicyParser()

# CLASS - CSRSigningParser
class CSRSigningParser(PolicyParser):
    """
    Parser for certificate signing operations. (rw)

    Handles CA keys, validity periods, and the path to the CSR file.
    """

    def _setup_parser(self) -> None:
        """Configure arguments for the signing process. (rw)"""
        super()._setup_parser()
        self.add_argument("-k", "--key", "--private-key", dest="private_key")
        self.add_argument("--private-dir", dest="private_dir")
        self.add_argument(
            "-c",
            "--cert",
            "--certificate",
            dest="certificate",
            default="",
            help="Certificate to sign.",
        )
        self.add_argument(
            "-d",
            "--days",
            dest="validity_days",
            type=int,
            default=365,
            help="Days of validity of the signed certificate (Default: %(default)s)",
        )
        self.add_argument(
            "-P",
            "--path-length",
            dest="path_length",
            type=int,
            default=0,
            help="Length of the path for intermediate certificates.",
        )
        self.add_argument("passphrasefile")
        self.add_argument("certificat_sign_request")

    def parse_args(
        self, args: list[str] | None = None, namespace: Namespace | None = None
    ) -> SignParserProtocol:
        """
        Parse arguments and return a signing protocol object. (rw)

        :returns: An object following the SignParserProtocol.
        """
        return cast(SignParserProtocol, super().parse_args(args=args, namespace=namespace))
# !CLASS - CSRSigningParser


def get_csr_signing_parser() -> CSRSigningParser:
    """
    Factory function to create a CSRSigningParser instance.

    :returns: A new instance of the certificate signing parser.
    """
    return CSRSigningParser()

# CLASS - CSRMultiSigningParser
class CSRMultiSigningParser(CSRSigningParser):
    """
    Parser for signing operations involving multiple policy types. (rw)
    """

    def _setup_parser(self) -> None:
        """Add policy type selection to the signing parser. (rw)"""
        super()._setup_parser()
        self.add_argument(
            "-t",
            "--policy-type",
            dest="policy_type",
            choices=["intermediate", "server", "user", "client", "standalone"],
            default="server",
            help="The type of the policy. (Default: %(default)s)",
        )

    def parse_args(
        self, args: list[str] | None = None, namespace: Namespace | None = None
    ) -> MultiSignParserProtocol:
        """
        Parse arguments and return a multi-policy signing object. (rw)

        :returns: An object following the MultiSignParserProtocol.
        """
        return cast(MultiSignParserProtocol, super().parse_args(args=args, namespace=namespace))
# !CLASS - CSRMultiSigningParser


def get_csr_multi_sign_parser() -> CSRMultiSigningParser:
    """
    Factory function to create a CSRMultiSigningParser instance.

    :returns: A new instance of the multi-policy signing parser.
    """
    return CSRMultiSigningParser()

# CLASS - CertImportParser
class CertImportParser(ArgparseFix311):
    """
    Parser for importing certificates from encrypted archives. (rw)
    """

    def __init__(
        self,
        prog: str | None = None,
        usage: str | None = None,
        description: str | None = None,
        epilog: str | None = None,
        exit_on_error: bool = False,
        argument_default="",
        **kwargs,
    ) -> None:
        """Initialize the import parser. (rw)"""
        super().__init__(prog, usage, description, epilog, exit_on_error=exit_on_error, **kwargs)
        self._setup_parser()

    def _setup_parser(self) -> None:
        """Configure positional and required key arguments for import. (rw)"""
        self.add_argument("enc_zipfile", help="Encrypted certificate zipfile.")
        self.add_argument(
            "--keyfile", "-k", dest="private_keyfile", required=True, help="Name des Private Keys"
        )

    def parse_args(
        self, args: list[str] | None = None, namespace: Namespace | None = None
    ) -> CertImportProtocol:
        """
        Parse arguments and return a certificate import object. (rw)

        :returns: An object following the CertImportProtocol.
        """
        return cast(CertImportProtocol, super().parse_args(args, namespace))
# !CLASS - CertImportParser


def get_cert_import_parser() -> CertImportParser:
    """
    Factory function to create a CertImportParser instance.

    :returns: A new instance of the certificate import parser.
    """
    return CertImportParser()

# CLASS - IntermedImportParser
class IntermedImportParser(CertImportParser):
    """
    Parser for importing intermediate CA certificates. (rw)
    """

    def _setup_parser(self) -> None:
        """Add passphrase and policy options for intermediate import. (rw)"""
        self.add_argument("passphrase_file", help="Name of the file with the passphrase")
        super()._setup_parser()
        self.add_argument(
            "--policies",
            default="",
            dest="policies",
            help="Directory with policy files",
        )
        self.add_argument(
            "-p",
            "--policy",
            dest="policy",
            help="The name of the policy to use",
            required=True,
        )

    def parse_args(
        self, args: list[str] | None = None, namespace: Namespace | None = None
    ) -> IntermedImportProtocol:
        """
        Parse arguments and return an intermediate import object. (rw)

        :returns: An object following the IntermedImportProtocol.
        """
        return cast(IntermedImportProtocol, super().parse_args(args, namespace))
# !CLASS - IntermedImportParser


def get_intermed_import_parser() -> IntermedImportParser:
    """
    Factory function to create a CertImportParser instance.

    :returns: A new instance of the certificate import parser.
    """
    return IntermedImportParser()

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
    test_file = testfiles_dir / "get_started_cli_parser.rst"

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
