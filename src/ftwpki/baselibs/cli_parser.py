# File: src/ftwpki/baselibs/cli_parser.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
cli_parser
===============================


Modul cli_parser documentation
"""

from argparse import Action, ArgumentError, ArgumentParser, Namespace
from pathlib import Path
from typing import cast

from ftwpki.baselibs.protocols import (
    CSRProtocol,
    DistinguishedNameProtocol,
    PolicyProtocol,
    SigningProtocol,
)

ALIAS_MAP = {
    "C": "countryName",
    "ST": "stateOrProvinceName",
    "O": "organizationName",
    "CN": "commonName",
    "L": "localityName",
    "OU": "organizationalUnitName",
}


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


class DistinguishedNameParser(ArgumentParser):
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


class PolicyParser(ArgumentParser):
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
        fields = {
            "C": "countryName",
            "ST": "stateOrProvinceName",
            "L": "localityName",
            "O": "organizationName",
            "OU": "organizationalUnitName",
            "CN": "commonName",
        }

        choices = ["match", "optional", "supplied", "no"]

        for alias, full_name in fields.items():
            self.add_argument(
                f"-{alias}",
                f"--{full_name}",
                dest=full_name,
                choices=choices,
                default="no",
                help=f"Policy für {full_name} (Default: %(default)s)",
            )
        self.add_argument(
            "-P",
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
        return cast(PolicyProtocol, super().parse_args(args=args, namespace=namespace))


class CSRSigningParser(PolicyParser):
    def _setup_parser(self) -> None:
        super()._setup_parser()
        self.add_argument("-k", "--key", "--private-key", dest="private_key")
        self.add_argument("--private-dir", dest="private_dir")

    def parse_args(
        self, args: list[str] | None = None, namespace: Namespace | None = None
    ) -> SigningProtocol:
        return cast(SigningProtocol, super().parse_args(args=args, namespace=namespace))


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
