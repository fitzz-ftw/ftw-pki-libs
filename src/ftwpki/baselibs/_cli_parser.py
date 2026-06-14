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
from copy import deepcopy
from pathlib import Path
from tomllib import load
from typing import Any, Callable, Generic, TypeAlias, TypeVar

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


def load_help_entries(constance: dict[str, Any], help_file: Path) -> None:
    # if not constance:
    with help_file.open("rb") as f:
        constance.update(load(f))


# !FUNCTION - get_help_entries

_HELP: dict[str, Any] = {}

load_help_entries(_HELP, HELP_FILE)


#!SECTION - ArgumentParser help
LANG = "en"


def parser_factory_creator(arg_type:type['BaseArguments']) -> Callable[..., Any]:  
    def parser_factory(pre_parser:bool=False, **kwargs) -> PKIBaseParser:
        kwargs["arg_conf"] = arg_type
        parser = PKIBaseParser(pre_parser=pre_parser, **kwargs)
        return parser
    parser_factory.__doc__ = f"Factory-Funktion für {arg_type.__name__}Parser."
    return parser_factory

# CLASS - ParserHelp
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
        ret = self._help.get(arg_dest_name, "")  # type: ignore
        return ret.get(self._lang, "en") if ret else ret  # type: ignore

    def __call__(self, arg_dest_name: str) -> str:
        """
        Return the help text for the given argument destination.

        :param arg_dest_name: The destination name of the argument.
        :returns: The help text.
        """
        return self.help(arg_dest_name)


# !CLASS - ParserHelp


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


# CLASS - KeyNames Mixin
class KeyNames:
    @property
    def private_key(self):
        return f"{self.key_name}.key.pem" if hasattr(self, "key_name") else None  # type: ignore

    @property
    def public_key(self):
        return f"{self.key_name}.pub.pem" if hasattr(self, "key_name") else None  # type: ignore


# !CLASS - KeyNames Mixin


# CLASS - BaseArguments
class BaseArguments:
    __slots__: list[str] = ["_arguments"]
    helpid: list[str] = []
    arg_data = {}

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        base = cls.__base__ if cls.__base__ is not None else BaseArguments
        base_slots: list = base.__slots__.copy()
        base_slots.extend(cls.__slots__.copy())
        base_helpid: list = base.helpid.copy()
        base_helpid.extend(cls.helpid)
        base_data: dict = deepcopy(base.arg_data)
        base_data.update(cls.arg_data)
        cls.__slots__ = base_slots
        cls.arg_data = base_data
        cls.helpid = base_helpid

    @property
    def arguments(self) -> list[tuple[list[str], dict[str,Any]]]:
        if hasattr(self, "_arguments"):
            return self._arguments
        else:
            return []

    def setup_args(self, pre_parser: bool = False):
        types = self.get_types()
        if hasattr(self, "_arguments"):
            del self._arguments
        self._arguments:list[tuple(list[str], dict[str, Any])] = []
        pre: bool = pre_parser
        help = ParserHelp(self.helpid[0], _HELP)
        for helpname in self.helpid[1:]:
            help.update(helpname)
        for name in self.arg_data:
            args = []
            kwargs = {}
            self.arg_data[name]["kws"].update(types[name]["kws"])
            args = self.arg_data[name]["flags"].copy()
            kwargs = deepcopy(self.arg_data[name]["kws"])
            if pre:
                kwargs.update(self.arg_data[name]["pre"])
            kwargs["help"] = help(name)
            if not args:
                args.append(name)
            else:
                kwargs["dest"] = name if args[0].startswith("-") else None
            entry = (args, kwargs)
            self._arguments.append(entry)


    def get_types(self):
        values: dict[str, dict[str, dict[str, type | str]]] = {}
        for name in [arg for arg in self.__slots__ if not arg.startswith("_")]:
            if name == "dnsubject":
                values[name] = {"kws": {"type": str}}
            else:
                curr_type = getattr(self, name)
                if isinstance(curr_type, list):
                    if not curr_type:
                        type_hint = str
                    else:
                        type_hint = type(curr_type[0])
                else:
                    type_hint = type(curr_type)
                values[name] = {
                    "kws": {"type": type_hint}
                }  
            del name
        return values

    def __repr__(self) -> str:
        names: list[str] = []
        self.__slots__.sort()
        for name in [arg for arg in self.__slots__ if not arg.startswith("_")]:
            if name in ["dnsubject", "host_names", "ip_addresses"]:
                names.append(f"{name}={getattr(self, name)}")
            else:
                names.append(f"{name}='{getattr(self, name)}'")
        ret = "".join(
            [
                f"{self.__class__.__name__}(",
                "\n".join(names),
                ")",
            ]
        )
        return ret


# !CLASS - BaseArguments


# CLASS - DistinguishedNameArguments
class DistinguishedNameArguments(BaseArguments):
    __slots__ = [
        "countryName",
        "stateOrProvinceName",
        "localityName",
        "organizationName",
        "organizationalUnitName",
        "commonName",
        "dnsubject",
    ]
    helpid: list[str] = [
        "desting-name",
    ]
    arg_data = {
        "countryName": {
            "flags": ["-C", "--countryName"],
            "kws": {
                "default": "",
                "sub_parser": "dn",
            },
            "pre": {},
        },
        "stateOrProvinceName": {
            "flags": ["-ST", "--stateOrProvinceName"],
            "kws": {
                "default": "",
                "sub_parser": "dn",
            },
            "pre": {},
        },
        "localityName": {
            "flags": ["-L", "--localityName"],
            "kws": {
                "default": "",
                "sub_parser": "dn",
            },
            "pre": {},
        },
        "organizationName": {
            "flags": ["-O", "--organizationName"],
            "kws": {
                "default": "",
                "sub_parser": "dn",
            },
            "pre": {},
        },
        "organizationalUnitName": {
            "flags": ["-OU", "--organizationalUnitName"],
            "kws": {
                "default": "",
                "sub_parser": "dn",
            },
            "pre": {},
        },
        "commonName": {
            "flags": ["-CN", "--commonName"],
            "kws": {
                "default": "",
                "sub_parser": "dn",
            },
            "pre": {},
        },
        "dnsubject": {
            "flags": ["-subj"],
            "kws": {
                "default": "",
                "action": SubjAction,
                "sub_parser": "dn",
            },
            "pre": {},
        },
    }

    def __init__(self) -> None:
        self.countryName: str = ""
        self.localityName: str = ""
        self.organizationName: str = ""
        self.stateOrProvinceName: str = ""
        self.organizationalUnitName: str = ""
        self.commonName: str = ""
        self.dnsubject: dict[str, str] = {}

    def sync_arguments(
        self,
    ) -> None:
        """
        Synchronize individual DN flags with the dnsubject dictionary. (rw)

        :param parsed_args: The namespace object containing parsed attributes.
        :returns: The updated protocol-compliant object.
        """

        final_dn: dict[str, str] = self.dnsubject or {}
        args = DistinguishedNameArguments.__slots__.copy()
        args.remove("dnsubject")
        for arg in args:
            arg_v = getattr(self, arg, "")
            if arg_v:
                final_dn[arg] = arg_v
            else:
                dn_arg = final_dn.get(arg, "")
                if dn_arg:
                    setattr(self, arg, final_dn[arg])
        self.dnsubject = final_dn

    # def __repr__(self) -> str:

    #     names: list[str] = []
    #     self.__slots__.sort()
    #     for name in self.__slots__:
    #         if name in ["dnsubject", "host_names", "ip_addresses"]:
    #             names.append(f"{name}={getattr(self, name)}")
    #         else:
    #             names.append(f"{name}='{getattr(self, name)}'")
    #     ret = "".join(
    #         [
    #             f"{self.__class__.__name__}(",
    #             "\n".join(names),
    #             ")",
    #         ]
    #     )
    #     return ret


# !CLASS - DistinguishedNameArguments

DisNam: TypeAlias = DistinguishedNameArguments

# CLASS - CSRArguments
class CSRArguments(DistinguishedNameArguments, KeyNames):
    __slots__ = [
        "conf_file",
        "key_name",
        "pki_name",
        "privatdir",
    ]
    helpid: list[str] = [
        "csrparser",
    ]
    arg_data = {
        "conf_file": {
            "flags": ["--conf-file"],
            "kws": {"required": True},
            "pre": {"required": False},
        },
        "key_name": {
            "flags": ["-k", "--key", "--key-name"],
            "kws": {"default": "", "required": True},
            "pre": {"required": False},
        },
        "pki_name": {
            "flags": ["-n", "--name"],
            "kws": {
                "default": "",
            },
            "pre": {},
        },
        "privatdir": {
            "flags": ["--private-dir"],
            "kws": {
                "default": "",
            },
            "pre": {},
        },
    }

    def __init__(self) -> None:
        super().__init__()
        self.conf_file: Path = Path()
        self.key_name: str = ""
        self.pki_name: str = ""
        self.privatdir: str = ""


# !CLASS - CSRArguments

CSR: TypeAlias = CSRArguments

# CLASS - ServerClientCSRArguments
class ServerClientCSRArguments(CSRArguments):
    __slots__ = [
        "ip_addresses",
        "host_names",
        "password",
        "email"
    ]
    helpid: list[str] = [
        "servclientcsr",
    ]
    arg_data = {
        "email": {
            "flags": [],
            "kws": {},
            "pre": {"nargs":"?"},
        },
        "ip_addresses": {
            "flags": ["-ip", "--ip-address"],
            "kws": {
                "action": "append",
                "default": [],
                "sub_parser": "san",
            },
            "pre": {},
        },
        "host_names": {
            "flags": ["-dns", "--host-name"],
            "kws": {
                "action": "append",
                "default": [],
                "sub_parser": "dn",
            },
            "pre": {},
        },
        "password": {
            "flags": ["--password"],
            "kws": {},
            "pre": {},
        },
    }

    def __init__(self) -> None:
        super().__init__()
        self.ip_addresses: list[str] = []
        self.host_names: list[str] = []
        self.password: str = ""
        self.email:str =""


# !CLASS - ServerClientCSRArguments

SCCSR: TypeAlias = ServerClientCSRArguments

# CLASS - CertImportArguments
class CertImportArguments(BaseArguments, KeyNames):
    __slots__ = [
        "enc_zipfile",
        "key_name",
    ]
    helpid: list[str] = [
        "certimport",
    ]
    arg_data = {
        "enc_zipfile": {
            "flags": [],
            "kws": {"metavar": "encrypted-zip-file"},
            "pre": {"nargs": "?"},
        },
        "key_name": {
            "flags": [
                "--key-name",
                "-k",
            ],
            "kws": {
                "default": "password.txt",
                "required": True,
            },
            "pre": {"required": False},
        },
    }

    def __init__(self) -> None:
        self.enc_zipfile: str = ""
        self.key_name: str = ""

    # def __repr__(self) -> str:

    #     names: list[str] = []
    #     self.__slots__.sort()
    #     for name in self.__slots__:
    #         names.append(f"{name}='{getattr(self, name)}'")
    #     ret = "".join(
    #         [
    #             f"{self.__class__.__name__}(",
    #             "\n".join(names),
    #             ")",
    #         ]
    #     )
    #     return ret


# !CLASS - CertImportArguments

CrtImp: TypeAlias = CertImportArguments

# CLASS - IntermedImportArguments


class IntermedImportArguments(CertImportArguments):
    __slots__ = [
        "policies",
        "policy",
    ]
    helpid: list[str] = ["intermcertimport"]  # CertImportArguments.helpid.copy()
    arg_data = {
        "policies": {
            "flags": [
                "--policies-dir",
            ],
            "kws": {"default": ""},
            "pre": {},
        },
        "policy": {
            "flags": ["-p", "--policy"],
            "kws": {
                "required": True,
            },
            "pre": {"required": False},
        },
    }

    def __init__(self) -> None:
        super().__init__()
        self.policies: str = ""
        self.policy: str = ""


# !CLASS - IntermedImportArguments

IntImp: TypeAlias = IntermedImportArguments

# CLASS - PolicyArguments
class PolicyArguments(BaseArguments):
    __slots__ = [
        "countryName",
        "stateOrProvinceName",
        "localityName",
        "organizationName",
        "organizationalUnitName",
        "commonName",
        "policy_name",
        "conf_file",
    ]
    helpid: list[str] = [
        "policy",
    ]
    arg_data = {
        "countryName": {
            "flags": ["-C", "--countryName"],
            "kws": {"choices": ["match", "optional", "supplied", "no"], "default": "no"},
            "pre": {},
        },
        "stateOrProvinceName": {
            "flags": ["-ST", "--stateOrProvinceName"],
            "kws": {"choices": ["match", "optional", "supplied", "no"], "default": "no"},
            "pre": {},
        },
        "localityName": {
            "flags": ["-L", "--localityName"],
            "kws": {"choices": ["match", "optional", "supplied", "no"], "default": "no"},
            "pre": {},
        },
        "organizationName": {
            "flags": ["-O", "--organizationName"],
            "kws": {"choices": ["match", "optional", "supplied", "no"], "default": "no"},
            "pre": {},
        },
        "organizationalUnitName": {
            "flags": ["-OU", "--organizationalUnitName"],
            "kws": {"choices": ["match", "optional", "supplied", "no"], "default": "no"},
            "pre": {},
        },
        "commonName": {
            "flags": ["-CN", "--commonName"],
            "kws": {"choices": ["match", "optional", "supplied", "no"], "default": "no"},
            "pre": {},
        },
        "policy_name": {
            "flags": [
                "-p",
                "--policy-name",
            ],
            "kws": {"default": None},
            "pre": {},
        },
        "conf_file": {
            "flags": ["--conf-file"],
            "kws": {},
            "pre": {},
        },
    }

    def __init__(self) -> None:
        self.countryName: str = "no"
        self.localityName: str = "no"
        self.organizationName: str = "no"
        self.stateOrProvinceName: str = "no"
        self.organizationalUnitName: str = "no"
        self.commonName: str = "no"
        self.policy_name: str = ""
        self.conf_file: Path = Path()

    def policy(self, entryname: str):
        return getattr(self, entryname)


# !CLASS - PolicyArguments

Pol: TypeAlias = PolicyArguments

# CLASS - CSRSigningArguments
class CSRSigningArguments(PolicyArguments, KeyNames):
    __slots__ = [
        "key_name",
        "private_dir",
        "certificate",
        "validity_days",
        "path_length",
        "passphrasefile",
        "certificat_sign_request",
    ]
    helpid: list[str] = [
        "csrsigning",
    ]
    arg_data = {
        "key_name": {
            "flags": ["-k", "--key", "--key-name"],
            "kws": {},
            "pre": {},
        },
        "private_dir": {
            "flags": ["--private-dir"],
            "kws": {},
            "pre": {},
        },
        "certificate": {
            "flags": ["-c", "--cert", "--certificate"],
            "kws": {"required": True},
            "pre": {"required": False},
        },
        "validity_days": {
            "flags": ["-d", "--days"],
            "kws": {
                "default": 365,
            },
            "pre": {},
        },
        "path_length": {
            "flags": ["-P", "--path-length"],
            "kws": {
                "default": 0,
            },
            "pre": {},
        },
        "passphrasefile": {
            "flags": [],
            "kws": {"metavar": "passphrase-file"},
            "pre": {"nargs": "?"},
        },
        "certificat_sign_request": {
            "flags": ["-subj"],
            "kws": {"metavar": "CSR-file"},
            "pre": {"nargs": "?"},
        },
    }

    def __init__(self) -> None:
        super().__init__()
        self.key_name: str = ""
        self.private_dir: str = ""
        self.certificate: str = ""
        self.validity_days: int = 365
        self.path_length: int = 0
        self.passphrasefile: str = ""
        self.certificat_sign_request: str = ""


# !CLASS - CSRSigningArguments

CSRSig: TypeAlias = CSRSigningArguments

# CLASS - CSRMultiSigningArguments
class CSRMultiSigningArguments(CSRSigningArguments):
    __slots__ = [
        "policy_type",
    ]
    helpid: list[str] = [
        "csrsigning",
    ]
    arg_data = {
        "policy_type": {
            "flags": ["-t", "--policy-type"],
            "kws": {
                "choices": ["intermediate", "server", "user", "client", "standalone"],
                "default": "server",
            },
            "pre": {},
        },
    }

    def __init__(self) -> None:
        super().__init__()
        self.policy_type: str = ""


# !CLASS - CSRMultiSigningArguments

CSRMul: TypeAlias = CSRMultiSigningArguments

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
        else:
            super().error(message)  # not py 3.11 no·‌cover

    def exit(self, status=0, message=None):
        """
        Intercept exit calls to maintain control flow. (rw)

        :param status: Exit status code.
        :param message: Optional error message.
        """
        if sys.version_info[:2] == (3, 11) and status != 0:  # py 3.11 only no cover
            self.error(message or f"Exited with status {status}")
        else:
            super().exit(status, message)  # not py 3.11 no cover


# !CLASS - ArgparseFix311

AT=TypeVar("AT", bound='BaseArguments' )

# CLASS - PKIBaseParser
class PKIBaseParser(ArgparseFix311,Generic[AT]):
    """
    CLI for encrypting password files using the PasswordManager. (rw)

    Provides a parser to handle target filenames, source passphrase files,
    and output directories.
    """

    def __init__(
        self,
        pre_parser: bool = False,
        *,
        arg_conf: AT = BaseArguments,
        exit_on_error: bool = False,
        **kwargs,
    ) -> None:
        """
        Initialize the parser with a default or custom description. (rw)
        """
        if pre_parser and "add_help" not in kwargs:
            kwargs["add_help"] = False
        self._preparser: bool = not kwargs.get("add_help", True)
        kwargs["exit_on_error"] = exit_on_error
        super().__init__(**kwargs)
        self._conf: AT = arg_conf()
        self._conf.get_types()
        # print(f"{self._preparser=}")
        self._conf.setup_args(pre_parser=self._preparser)
        self._san = self.add_argument_group("SAN Entries")
        self._dn = self.add_argument_group("Destinguish Name Entires")
        self._mandantory_san = True
        self._start_o_s_a = deepcopy(self._option_string_actions)
        self._start_actions =deepcopy(self._actions)
        self._setup_parser()

    def _setup_parser(self) -> None:
        """
        Configure the argument parser for target, source, and output directory. (ro)

        Sets up the positional and optional arguments for the CLI.
        """
        for name_flags, parser_config in self._conf.arguments:
            sub = parser_config.pop("sub_parser", None)
            match sub:
                case "dn":
                    self._dn.add_argument(*name_flags, **parser_config)
                case "san":
                    self._san.add_argument(*name_flags, **parser_config)
                case _:
                    self.add_argument(*name_flags, **parser_config)

    def parse_known_args(self, 
                         args: list[str] | None = None, 
                         namespace: AT | None = None) -> tuple[AT, list[str]]:
        return super().parse_known_args(args=args,namespace=namespace)

    def parse_args(
        self,
        args: list[str] | None = None,
        namespace: AT | None = None,
    ) -> AT:
        """
        Parse command-line arguments and cast to PasswordFileProtocol. (ro)

        :param args: List of argument strings.
        :param namespace: Existing namespace to populate.
        :returns: Parsed arguments adhering to PasswordFileProtocol.
        """
        if namespace is None:
            target_args = type(self._conf)
            namespace = target_args()

        for action in self._actions:
            if action.dest in namespace.__slots__:
                setattr(namespace, action.dest, action.default)
        ret = super().parse_args(args, namespace)
        if isinstance(ret, ServerClientCSRArguments):
            if not ret.ip_addresses and not ret.host_names and self._mandantory_san:
                raise ArgumentError(None, "At least an ip address or a hostname has to be given")
        if isinstance(ret, DistinguishedNameArguments):
            ret.sync_arguments()
        return ret

    @property
    def pre_parser(self)->bool:
        return self._preparser

    @property
    def mandantory_san(self) -> bool:
        """
        Check if Subject Alternative Names are mandatory. (rw)

        :param value: The boolean value to set.
        :returns: True if SAN entries are required, False otherwise.
        """
        return self._mandantory_san

    @mandantory_san.setter
    def mandantory_san(self, value: bool):
        """
        Check if Subject Alternative Names are mandatory. (rw)

        :param value: The boolean value to set.
        :returns: True if SAN entries are required, False otherwise.
        """
        self._mandantory_san = value


# !CLASS - PKIBaseParser

server_client_parser = parser_factory_creator(ServerClientCSRArguments)



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
        "debug_parser.rst",
        "get_started_new_parser.rst",
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
