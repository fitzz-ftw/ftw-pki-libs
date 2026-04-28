# File: src/ftwpki/baselibs/cli_parser.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
cli_parser
===============================


Modul cli_parser documentation
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
    CSRProtocol,
    DistinguishedNameProtocol,
    IntermedImportProtocol,
    MultiSignParserProtocol,
    PolicyProtocol,
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

# ArgumentParser().error()

class SubjAction(Action):
    @staticmethod
    def _parse_subj_string(subj_str) -> dict[str, str]:
        # Trenne bei / oder , und filtere leere Fragmente
        parts = [p.strip() for p in subj_str.replace(",", "/").split("/") if p.strip()]
        subj_dict = {}
        for part in parts:
            if "=" not in part:
                # Optional: Fehler werfen oder ignorieren
                raise ValueError(
                    f"Fragment '{part}' does not contain '=' (Expected format: Key=Value)"
                )

            key, value = part.split("=", 1)
            key = key.strip()
            # Mapping auf Langnamen (CN -> commonName)
            long_name = ALIAS_MAP.get(key, key)
            subj_dict[long_name] = value.strip()

        return subj_dict

    def __call__(self, parser, namespace, values, option_string=None):
        try:
            subj_dict = self._parse_subj_string(values)
            setattr(namespace, self.dest, subj_dict)
        except Exception as e:
            raise ArgumentError(self, f"Ungültiges Subj-Format: {e}")

class ArgparseFix311(ArgumentParser):
    """
    Fix for Python 3.11 argparse behavior where exit_on_error=False
    is sometimes ignored, leading to SystemExit instead of ArgumentError.
    """

    def error(self, message):
        if sys.version_info[:2] == (3, 11): # py 3.11 only no cover
            # Force ArgumentError to satisfy doctests and library usage
            raise ArgumentError(None, message)
        super().error(message)  # not py 3.11 no cover

    def exit(self, status=0, message=None):
        if sys.version_info[:2] == (3, 11) and status != 0:  # py 3.11 only no cover
            self.error(message or f"Exited with status {status}")
        super().exit(status, message)  # not py 3.11 no cover


class DistinguishedNameParser(ArgparseFix311):
    def __init__(
        self,
        prog: str | None = None,
        usage: str | None = None,
        description: str | None = None,
        epilog: str | None = None,
        exit_on_error: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(prog, usage, description, epilog, exit_on_error=exit_on_error, **kwargs)
        self._setup_parser()

    def _setup_parser(self) -> None:
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
        arg_parsed = cast(
            DistinguishedNameProtocol, super().parse_args(args=args, namespace=namespace)
        )
        return self.sync_arguments(arg_parsed)


class CSRParser(DistinguishedNameParser):
    def _setup_parser(self) -> None:
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
        return cast(CSRProtocol, super().parse_args(args, namespace))


class PolicyParser(ArgparseFix311):
    """
    Parser für Zertifikats-Policies.
    Legt fest, wie mit DN-Feldern bei der Signierung verfahren wird.
    """

    def __init__(self, **kwargs) -> None:
        # Falls exit_on_error nicht in kwargs, setzen wir es auf False wie im DN-Parser
        kwargs.setdefault("exit_on_error", False)
        super().__init__(**kwargs)
        self._setup_parser()

    def _setup_parser(self) -> None:
        # Die Felder, die wir aus dem DistinguishedNameParser kennen
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
        ret_args = cast(PolicyProtocol, super().parse_args(args=args, namespace=namespace))
        ret_args.policy = {}
        for v in self.fields.values():
            ret_args.policy[v] = getattr(ret_args, v, "no")
        return cast(PolicyProtocol, ret_args)


class CSRSigningParser(PolicyParser):

    def _setup_parser(self) -> None:
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
        return cast(SignParserProtocol, super().parse_args(args=args, namespace=namespace))

class CSRMultiSigningParser(CSRSigningParser):
    def _setup_parser(self) -> None:
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
        return cast(MultiSignParserProtocol, super().parse_args(args=args, namespace=namespace))


class CertImportParser(ArgparseFix311):
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
        super().__init__(prog, usage, description, epilog, exit_on_error=exit_on_error, **kwargs)
        self._setup_parser()

    def _setup_parser(self) -> None:
        self.add_argument("enc_zipfile",
                          help="Encrypted certifikate zipfile.")
        self.add_argument(
            "--keyfile", "-k", 
            dest="private_keyfile",
            required=True, 
            help="Name des Private Keys"
        )

    def parse_args(self, args: list[str] | None = None, 
                   namespace: Namespace|None=None) -> CertImportProtocol:
        return cast(CertImportProtocol, 
                    super().parse_args(args,namespace))


class IntermedImportParser(CertImportParser):

    def _setup_parser(self) -> None:
        self.add_argument("passphrase_file", help="Name of the file with teh passphrase")
        super()._setup_parser()
        self.add_argument(
            "--policies",
            default="",
            dest="policies",
            help="Directory with poicies files",
        )
        self.add_argument(
            "-p", "--policy", 
            dest="policy", 
            help="The name of the policy to use", 
            required=True,
        )

    def parse_args(self, args: list[str] | None = None, 
                   namespace: Namespace|None=None) -> IntermedImportProtocol:
        return cast(IntermedImportProtocol,
                    super().parse_args(args, namespace))


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
