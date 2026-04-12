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

from ftwpki.baselibs.protocols import DistinguishedNameProtocol

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
    def __init__(self, 
                 prog: str | None = None, 
                 usage: str | None = None, 
                 description: str | None = None, 
                 epilog: str | None = None, 
                 exit_on_error: bool = False,
                 **kwargs) -> None:
        super().__init__(prog, 
        usage, 
        description, 
        epilog, 
        exit_on_error=exit_on_error,
        **kwargs 
        )
        self._setup_parser()

    def _setup_parser(self) -> None:
        self.add_argument(
            "-C", 
            "--countryName", 
            dest="countryName",
            default="", 
            help="Land (2 Buchstaben)")
        self.add_argument(
            "-ST",
            "--stateOrProvinceName",
            dest="stateOrProvinceName",
            default="",
            help="Bundesland/Provinz",
        )
        self.add_argument(
            "-L", 
            "--localityName", 
            dest="localityName", 
            default="", 
            help="Stadt/Ort"
        )
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
            type= Path,
            help="Path to a TOML-Configfile",
        )

    def sync_arguments(self, parsed_args:DistinguishedNameProtocol) -> DistinguishedNameProtocol:
        final_dn = getattr(parsed_args, "dnsubject", {}) or {}
        for arg in ALIAS_MAP.values():
            arg_v = getattr(parsed_args,arg,"")
            if arg_v:
                final_dn[arg]= arg_v
            else:
                dn_arg=final_dn.get(arg, "")
                if dn_arg:
                    setattr(parsed_args, arg, final_dn[arg])
        parsed_args.dnsubject = final_dn
        return parsed_args

    def parse_args(self,args:list[str]| None=None, 
                   namespace:Namespace|None=None) -> DistinguishedNameProtocol:
        arg_parsed = cast(DistinguishedNameProtocol,
                          super().parse_args(args=args,namespace=namespace))
        return self.sync_arguments(arg_parsed)

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
