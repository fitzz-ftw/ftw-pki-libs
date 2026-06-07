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
    _ArgumentGroup,
)
from pathlib import Path
from tomllib import load
from typing import Any, cast

from ftwpki.baselibs.protocols import (
    CertImportProtocol,
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

# SECTION - ArgumentParser help
# FUNCTION - get_help_entries

HELP_FILE = Path(__file__).parent.joinpath("cli_parser.help")


def load_help_entries(constance: dict[str, Any], help_file: Path):
    # if not constance:
    with help_file.open("rb") as f:
        constance.update(load(f))


# !FUNCTION - get_help_entries

_HELP: dict[str, Any] = {}

load_help_entries(_HELP, HELP_FILE)

#!SECTION - ArgumentParser help
LANG = "en"


class ParserHelp:
    """Manage help text for parser arguments."""

    def __init__(
        self,
        parser_id: str,
        help_entries: dict[str, str | dict[str, str]] = _HELP,
        lang: str = LANG,
    ) -> None:
        """
        Initialize the help parser for a specific parser ID.

        :param parser_id: The unique identifier for the parser.
        :param help_entries: Dictionary containing the help content mappings.
        :param lang: The language code for the requested help text.
        """
        self._help = help_entries.get(parser_id)
        self._lang = lang

    def update(self, parser_id: str, new_help: dict[str, str | dict[str, str]] = _HELP) -> None:
        """
        Update the existing help entries with new content.

        :param parser_id: The identifier for the help entries to update.
        :param new_help: The dictionary containing new help mappings.
        """
        self._help.update(new_help.get(parser_id))  # type: ignore

    def help(self, arg_dest_name: str) -> str:
        """
        Retrieve the help text for a specific argument destination.

        :param arg_dest_name: The destination name of the argument.
        :returns: The help string for the specified language or an empty string.
        """
        ret = self._help.get(arg_dest_name, "") # type: ignore
        return ret.get(self._lang, "en") if ret else ret # type: ignore

    def __call__(self, arg_dest_name: str) -> str:
        """
        Return the help text for the given argument destination.

        :param arg_dest_name: The destination name of the argument.
        :returns: The help text.
        """
        return self.help(arg_dest_name)


class AutoHelpParserMixin:
    """
    Mixin to automate help text formatting.

    Provides a centralized add_argument method to inject dynamic
    metadata like required flags into the help strings.
    """

    def __init__(
        self, *args, help_id: str, help_entries: dict[str, str | dict[str, str]] = _HELP, **kwargs
    ):
        """
        Initialize the parser with integrated help functionality.

        :param help_id: The identifier for the help entries.
        :param help_entries: Mapping of parser IDs to help content.
        :param args: Positional arguments for the base class constructor.
        :param kwargs: Keyword arguments for the base class constructor.
        """
        # Hier injizieren wir unsere Custom-Klasse in den Constructor
        # if args and isinstance(args[0], ArgumentParser):
        #     print("Test")
        #     super().__init__(*args, **kwargs)
        # else:
        self._helpid: str = help_id
        # if hasattr(self, "_help"):
        #     self._help.update(help_entries[self._helpid])
        # else:
        self._help = ParserHelp(self._helpid, help_entries)
        super().__init__(*args, **kwargs)

    def add_argument(self, *args, **kwargs):
        """
        Add an argument to the parser and inject dynamic help text.

        :param args: Positional arguments for the argument definition.
        :param kwargs: Keyword arguments for the argument definition.
        :raises ValueError: If the argument destination cannot be resolved.
        """
        # Wenn dest explizit gegeben ist, nutzen wir es.
        # Sonst suchen wir den Namen aus den Flags.
        dest = kwargs.get("dest") or self._get_dest_from_args(args)

        # Hilfe-Text holen, wenn keiner angegeben ist
        if "help" not in kwargs and hasattr(self, "_help"):
            kwargs["help"] = self._help(dest)

        # Formatieren des Hilfe-Textes
        # if "help" in kwargs:
        is_required = kwargs.get("required", False)
        kwargs["help"] = kwargs["help"].format(required="(Required)" if is_required else "")

        super().add_argument(*args, **kwargs) # type: ignore

    def _get_dest_from_args(self, args):
        """
        Determine the destination name deterministically from arguments.

        :param args: Positional arguments used to define the option.
        :returns: The resolved destination name.
        """
        options = [a.lstrip("-") for a in args if a.startswith("-")]

        if options:
            # Wenn wir Optionen haben, nehmen wir den längsten als TOML-Key
            return max(options, key=len)
        else:
            # Wenn keine Optionen da sind, ist es ein Positional
            return args[0] if args else ""


# class AutoHelpGroup(AutoHelpParserMixin, _ArgumentGroup):
    # """
    # Custom ArgumentGroup that inherits help automation.

    # Allows groups to handle their own help string formatting seamlessly.
    # """

    # def __init__(self, container, *args, **kwargs):
    #     """
    #     Initialize the argument group and link help functionality from container.

    #     :param container: The parent container (usually an ArgumentParser) providing the help system.
    #     :param args: Positional arguments for the base class constructor.
    #     :param kwargs: Keyword arguments for the base class constructor.
    #     """
    #     super().__init__(container, *args, **kwargs)
    #     # Die Gruppe holt sich das ParserHelp Objekt vom Container (Parser)
    #     self._help = container._help


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

    def __call__(
        self,
        parser: ArgumentParser,
        namespace: Namespace,
        values: str,
        option_string: str | None = None,
    ):
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
        if sys.version_info[:2] == (3, 11):  # py 3.11 only no cover
            raise ArgumentError(None, message)
        super().error(message)  # not py 3.11 no·‌cover

    def exit(self, status=0, message=None):
        """
        Intercept exit calls to maintain control flow. (rw)

        :param status: Exit status code.
        :param message: Optional error message.
        """
        if sys.version_info[:2] == (3, 11) and status != 0:  # py 3.11 only no cover
            self.error(message or f"Exited with status {status}")
        super().exit(status, message)  # not py 3.11 no cover


# !CLASS - ArgparseFix311


# CLASS - DistinguishedNameParser
class DistinguishedNameParser(AutoHelpParserMixin, ArgparseFix311):
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
        run_setup: bool = True,
        exit_on_error: bool = False,
        **kwargs,
    ) -> None:
        """Initialize the DN parser with default PKI arguments. (rw)"""
        self._preparser: bool = not kwargs.get("add_help", True)
        args = [
            prog,
            usage,
            description,
            epilog,
        ]
        kwargs["exit_on_error"] = exit_on_error
        super().__init__(*args, help_id="desting-name", **kwargs)
        if run_setup:
            self._setup_parser()

    def _setup_parser(self) -> None:
        """Configure the available CLI arguments for DN attributes. (rw)"""
        help = self._help
        self.dn = self.add_argument_group("Destinguish Name Entires")
        self.dn.add_argument(
            "-C", "--countryName", dest="countryName", default="", help=help("countryName")
        )
        self.dn.add_argument(
            "-ST",
            "--stateOrProvinceName",
            dest="stateOrProvinceName",
            default="",
            help=help("stateOrProvinceName"),  # "Bundesland/Provinz",
        )
        self.dn.add_argument(
            "-L", "--localityName", dest="localityName", default="", help=help("localityName")
        )
        self.dn.add_argument(
            "-O",
            "--organizationName",
            dest="organizationName",
            default="",
            help=help("organizationName"),
        )
        self.dn.add_argument(
            "-OU",
            "--organizationalUnitName",
            dest="organizationalUnitName",
            default="",
            help=help("organizationalUnitName"),
        )
        self.dn.add_argument(
            "-CN",
            "--commonName",
            dest="commonName",
            default="",
            help=help("commonName"),  # "Vollqualifizierter Domainname (FQDN)",
        )
        self.dn.add_argument(
            "-subj",
            dest="dnsubject",
            default="",
            action=SubjAction,
            help=help("dnsubject"),  # "DN im OpenSSL-Format, z.B. /C=DE/O=Firma/CN=Server",
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

    def __init__(self, *args, run_setup: bool = True, **kwargs):
        """
        Initialize the CSR parser and configure help entries.

        :param run_setup: Whether to automatically run the parser configuration.
        :param args: Positional arguments for the base class constructor.
        :param kwargs: Keyword arguments for the base class constructor.
        """
        super().__init__(*args, run_setup=False, **kwargs)
        self._help.update("csrparser")
        if run_setup:
            self._setup_parser()

    def _setup_parser(self) -> None:
        """Configure additional arguments for CSR key paths. (rw)"""
        super()._setup_parser()
        self.add_argument(
            "--conf-file",
            dest="conf_file",
            type=Path,
            required=not self._preparser,
            help="Path to a TOML-Configfile",
        )
        self.add_argument(
            "-k", "--key", "--key-name", required=not self._preparser, default="", dest="key_name"
        )
        self.add_argument(
            "-n",
            "--name",
            default="",
            dest="pki_name",
            help="Name for the Configuration (Default: '%(default)s')",
        )
        self.add_argument("--private-dir", dest="privatdir", default="")

    def parse_args(
        self, args: list[str] | None = None, namespace: Namespace | None = None
    ) -> CSRProtocol:
        """
        Parse arguments and return a CSR protocol object. (rw)

        :param args: List of argument strings to parse.
        :param namespace: An optional Namespace object.
        :raises argparse.ArgumentError: If the arguments are invalid.
        :returns: An object following the CSRProtocol.
        """
        arg_parsed = cast(CSRProtocol, super().parse_args(args, namespace))
        base_name = arg_parsed.key_name
        arg_parsed.private_key = f"{base_name}.key.pem" if base_name else ""
        arg_parsed.public_key = f"{base_name}.pub.pem" if base_name else ""
        return cast(CSRProtocol, arg_parsed)


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

    def __init__(self, *args, run_setup: bool = True, **kwargs) -> None:
        """
        Initialize the ServerClient parser.

        :param run_setup: Whether to automatically run the parser configuration.
        :param args: Positional arguments for the base class constructor.
        :param kwargs: Arbitrary keyword arguments for the parser configuration.
        :raises KeyError: If required configuration keys are missing in kwargs.
        """
        self._mandantory_san = True
        kwargs.setdefault("exit_on_error", False)
        super().__init__(*args, run_setup=False, **kwargs)
        self._help.update("servclientcsr")
        if run_setup:
            self._setup_parser()

    @property
    def mandantory_san(self)->bool:
        """
        Check if Subject Alternative Names are mandatory. (rw)

        :param value: The boolean value to set.
        :returns: True if SAN entries are required, False otherwise.
        """
        return self._mandantory_san

    @mandantory_san.setter
    def mandantory_san(self, value:bool):
        """
        Check if Subject Alternative Names are mandatory. (rw)

        :param value: The boolean value to set.
        :returns: True if SAN entries are required, False otherwise.
        """
        self._mandantory_san = value


    def _setup_parser(self) -> None:
        """
        Configure the argument parser with specific network fields.

        :raises argparse.ArgumentError: If an argument conflict occurs.
        """
        super()._setup_parser()
        self.add_argument("email", nargs="?" if self._preparser else None, help=self._help("email"))
        self.san = self.add_argument_group("SAN Entries")
        self.san.add_argument(
            "-ip",
            "--ip-address",
            action="append",
            default=[],
            dest="ip_addresses",
            help=self._help("ip_addresses"),
        )
        self.san.add_argument(
            "-dns",
            "--host-name",
            action="append",
            default=[],
            dest="host_names",
            help=self._help("host_names"),  # f"The hostnames of the {self._type_name}.",
        )
        self.add_argument(
            "--password",
            dest="password",
            help=self._help("password"),  # "Password for the private key, on server dont use it."
        )

    def parse_args(
        self, args: list[str] | None = None, namespace: Namespace | None = None
    ) -> ServerClientCSRProtocol:
        """
        Parse command line arguments and validate network identity.

        :param args: List of strings to parse. Default is sys.argv.
        :param namespace: An object to take the attributes.
        :raises argparse.ArgumentError: If neither an IP address nor a hostname is provided.
        :returns: An object containing the parsed and validated CSR data.
        """
        ret = cast(ServerClientCSRProtocol, super().parse_args(args, namespace))
        if not ret.ip_addresses and not ret.host_names and self._mandantory_san:
            raise ArgumentError(None, "At least an ip address or a hostname has to be given")
        return ret


#!CLASS - ServerClientCSRParser


def get_server_client_csr_parser() -> ServerClientCSRParser:
    """
    Factory function to create a ServerClientCSRParser instance.

    :returns: A new instance of the Server/Client CSR parser.
    """
    return ServerClientCSRParser()


# CLASS - PolicyParser
class PolicyParser(AutoHelpParserMixin, ArgparseFix311):
    """
    Parser for certificate issuance policies. (rw)

    Defines how individual DN fields should be treated during signing
    (e.g., match, optional, supplied).
    """

    def __init__(self, *args, run_setup: bool = True, **kwargs) -> None:
        """Initialize the policy parser. (rw)"""
        self._preparser: bool = not kwargs.get("add_help", True)
        kwargs.setdefault("exit_on_error", False)
        super().__init__(*args, help_id="policy", **kwargs)
        if run_setup:
            self._setup_parser()

    def _setup_parser(self) -> None:
        """Configure arguments for policy constraint settings. (rw)"""
        self.dn_pol = self.add_argument_group("DN Security Policies")
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
            self.dn_pol.add_argument(
                f"-{alias}",
                f"--{full_name}",
                dest=full_name,
                choices=choices,
                default="no",
                help=self._help(full_name),  # f"Policy für {full_name} (Default: %(default)s)",
            )
        self.add_argument(
            "-p",
            "--policy-name",
            dest="policy_name",
            default=None,
            help=self._help("policy_name"),  # "Name of the policy. (Default: %(default)s)",
        )
        self.add_argument(
            "--conf-file",
            dest="conf_file",
            type=Path,
            help=self._help("conf_file"),  # "Path to a TOML-Configfile",
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

    def __init__(self, *args, run_setup: bool = True, **kwargs):
        """
        Initialize the CSR parser and configure help entries.

        :param run_setup: Whether to automatically run the parser configuration.
        :param args: Positional arguments for the base class constructor.
        :param kwargs: Keyword arguments for the base class constructor.
        """
        self._preparser: bool = not kwargs.get("add_help", True)
        super().__init__(*args, run_setup=False, **kwargs)
        self._help.update("csrsigning")
        if run_setup:
            self._setup_parser()

    def _setup_parser(self) -> None:
        """Configure additional arguments for CSR key paths. (rw)"""
        super()._setup_parser()
        self.add_argument("-k", "--key", "--key-name", dest="key_name", help=self._help("key_name"))
        # self.add_argument("-k", "--key", "--private-key", dest="private_key")
        self.add_argument("--private-dir", dest="private_dir", help=self._help("private_dir"))
        self.add_argument(
            "-c",
            "--cert",
            "--certificate",
            dest="certificate",
            default="",
            required= True if not self._preparser else False,
            help=self._help("certificate"),  # "Certificate used to sign the CSR.",
        )
        self.add_argument(
            "-d",
            "--days",
            dest="validity_days",
            type=int,
            default=365,
            help=self._help(
                "validity_days"
            ),  # "Days of validity of the signed certificate (Default: %(default)s)",
        )
        self.add_argument(
            "-P",
            "--path-length",
            dest="path_length",
            type=int,
            default=0,
            help=self._help("path_length"),  # "Length of the path for intermediate certificates.",
        )
        self.add_argument(
            "passphrasefile",
            nargs="?" if self._preparser else None,
            metavar="passphrase-file",
            help=self._help("passphrasefile"),  #
        )
        self.add_argument(
            "certificat_sign_request",
            nargs="?" if self._preparser else None,
            metavar="CSR-file",
            help=self._help("certificat_sign_request"),  #
        )

    def parse_args(
        self, args: list[str] | None = None, namespace: Namespace | None = None
    ) -> SignParserProtocol:
        """
        Parse arguments and return a CSR protocol object. (rw)

        :param args: List of argument strings to parse.
        :param namespace: An optional Namespace object.
        :raises argparse.ArgumentError: If the arguments are invalid.
        :returns: An object following the CSRProtocol.
        """
        arg_parsed = cast(SignParserProtocol, super().parse_args(args=args, namespace=namespace))
        base_name = arg_parsed.key_name
        arg_parsed.private_key = f"{base_name}.key.pem" if base_name else ""
        return cast(SignParserProtocol, arg_parsed)


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

    def __init__(self, *args, run_setup: bool = True, **kwargs):
        """
        Initialize the multi-signing parser.

        :param run_setup: Whether to automatically run the parser configuration.
        :param args: Positional arguments for the base class constructor.
        :param kwargs: Keyword arguments for the base class constructor.
        """
        self._preparser: bool = not kwargs.get("add_help", True)
        super().__init__(*args, run_setup=False, **kwargs)
        self._help.update("csrmultisign")
        if run_setup:
            self._setup_parser()

    def _setup_parser(self) -> None:
        """
        Add policy type selection to the signing parser. (rw)

        :raises argparse.ArgumentError: If an argument conflict occurs.
        """
        super()._setup_parser()
        self.add_argument(
            "-t",
            "--policy-type",
            dest="policy_type",
            choices=["intermediate", "server", "user", "client", "standalone"],
            default="server",
            help=self._help("policy_type"),  # "The type of the policy. (Default: %(default)s)",
        )

    def parse_args(
        self, args: list[str] | None = None, namespace: Namespace | None = None
    ) -> MultiSignParserProtocol:
        """
        Parse arguments and return a multi-policy signing object. (rw)

        :param args: List of strings to parse.
        :param namespace: An optional Namespace object.
        :raises argparse.ArgumentError: If the arguments are invalid.
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
class CertImportParser(AutoHelpParserMixin, ArgparseFix311):
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
        run_setup=True,
        argument_default="",
        **kwargs,
    ) -> None:
        """Initialize the import parser. (rw)"""
        self._preparser: bool = not kwargs.get("add_help", True)
        args = [
            prog,
            usage,
            description,
            epilog,
        ]
        kwargs["exit_on_error"] = exit_on_error
        super().__init__(*args, help_id="certimport", **kwargs)
        if run_setup:
            self._setup_parser()

    def _setup_parser(self) -> None:
        """Configure positional and required key arguments for import. (rw)"""
        self.add_argument(
            "enc_zipfile",
            metavar="encrypted-zip-file",
            help=self._help("enc_zipfile"),  # "Encrypted certificate zipfile."
        )
        self.add_argument(
            "--key-name",
            "-k",
            dest="key_name",
            required=True,
            help=self._help("key_name"),  # "Name des Private Keys"
        )

    def parse_args(
        self, args: list[str] | None = None, namespace: Namespace | None = None
    ) -> CertImportProtocol:
        """
        Parse arguments and return a certificate import object. (rw)

        :returns: An object following the CertImportProtocol.
        """
        arg_parsed = cast(CertImportProtocol, super().parse_args(args, namespace))
        base_name = arg_parsed.key_name
        arg_parsed.private_keyfile = f"{base_name}.key.pem" if base_name else ""
        return cast(CertImportProtocol, arg_parsed)


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

    def __init__(self, *args, run_setup: bool = True, **kwargs):
        """
        Initialize the intermediate certificate import parser.

        :param run_setup: Whether to automatically run the parser configuration.
        :param args: Positional arguments for the base class constructor.
        :param kwargs: Keyword arguments for the base class constructor.
        """
        super().__init__(*args, run_setup=False, **kwargs)
        self._help.update("intermcertimport")
        if run_setup:
            self._setup_parser()

    def _setup_parser(self) -> None:
        """Add passphrase and policy options for intermediate import. (rw)"""
        self.add_argument("passphrase_file", help="Name of the file with the passphrase")
        super()._setup_parser()
        self.add_argument(
            "--policies-dir",
            default="",
            dest="policies",
            help=self._help("policies"),  # "Directory with policy files",
        )
        self.add_argument(
            "-p",
            "--policy",
            dest="policy",
            help=self._help("policy"),  # "The name of the policy to use",
            required=True,
        )

    def parse_args(
        self, args: list[str] | None = None, namespace: Namespace | None = None
    ) -> IntermedImportProtocol:
        """
        Parse arguments and return an intermediate import object. (rw)

        :param args: List of strings to parse.
        :param namespace: An optional Namespace object.
        :raises argparse.ArgumentError: If the arguments are invalid.
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
    passed_files = 0

    # Pfad zu den dokumentierenden Tests
    testfiles_dir = Path(__file__).parents[3] / "doc/source/devel"

    test_files = [
        # "test_new_parser.rst",
        "get_started_cli_parser.rst",
    ]
    for file in test_files:
        test_file = testfiles_dir / file
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
            if doctestresult.failed > 0 and option_flags & FAIL_FAST:
                print(f"Doctest result for {test_file.name}: {doctestresult}")
                print(
                    f"\nKeep going! You already passed {passed_files} files "
                    f"with {test_sum} tests before this hit."
                )
                break  # Stop on first failure if FAIL_FAST is set
            passed_files += 1
        else:
            print(f"⚠️ Warning: Test file {test_file.name} not found.")
    if test_failed == 0:
        print(f"\nDocTests passed without errors, {test_sum} tests.")
    else:
        if not option_flags & FAIL_FAST:
            print(f"\nDocTests failed: {test_failed} tests out of {test_sum}.")
