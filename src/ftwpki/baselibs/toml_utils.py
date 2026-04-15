# File: src/ftwpki/baselibs/toml_utils.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
toml_utils
===============================


Modul toml_utils documentation
"""

import sys
from argparse import ArgumentError
from pathlib import Path
from tomllib import TOMLDecodeError, loads
from typing import NoReturn, cast


def list_policy_sections(data:dict, policy_type:str) -> bool:
    for k, v in data.items():
        if policy_type in v:
            print(k, flush=True)
    return True
    # raise ArgumentError(None,message="No or wrong policyname given")

def toml2dn(argv: list[str] | None = None, argname: str = "--conf_file") -> dict[str, str]:
    if argv is None:
        argv = sys.argv[1:]
    try:
        index = argv.index(argname)
    except ValueError:
        return {}
    try:
        tomlfile = Path(argv[index + 1])
        conf_str = tomlfile.read_text()
        tomfile = loads(conf_str)
    except FileNotFoundError:
        print(f"File '{argv[index + 1]}' not found!")
        return {"dnsubject": ""}
    except TOMLDecodeError:
        print(f"Could not decode file {argv[index + 1]}!")
        return {"dnsubject": ""}
    try:
        dn = tomfile["identity"]["dn"]
    except KeyError:
        print("No table 'identity.dn' in config file!")
        return {"dnsubject": ""}
    dn["dnsubject"] = ""
    return dn


def _get_toml_policy_data(argv: list[str] | None, 
                          argconfname: str,
                          argsecname:str,
                          policy_type:str,
                          filename: str | None,
                          section:str|None
                          ) -> dict:
    """Internal helper to find and load the TOML file."""
    toml_path_str = filename
    section_name = section
    if toml_path_str is None or section_name is None:
        if argv is None:
            argv = sys.argv[1:]
        try:
            if toml_path_str is None:
                index_conf = argv.index(argconfname)
                toml_path_str = argv[index_conf + 1]
            if section_name is None and argsecname in argv:
                index_section = argv.index(argsecname)
                section_name = argv[index_section + 1] if argsecname in argv else None
        except (ValueError, IndexError):
            return {}
    try:
        data:dict[str,dict] = loads(Path(toml_path_str).read_text())
    except (FileNotFoundError, TOMLDecodeError, Exception) as e:
        print(f"Error loading TOML '{toml_path_str}': {e}")
        return {}
    
    data = data.get("policy",{})
    if not section_name:
        list_policy_sections(data, policy_type)
        return {"commonName":"error"}
    else:
        section_name = cast(str, section_name)
        try:
            if policy_type == "ext": # pragma: no cover for future use
                extensions = data.get("ext", {}).copy()
                specific_ext = data.get(section_name, {}).get("ext", {})
                extensions.update(specific_ext)
                return extensions
            else:
                return data[section_name][policy_type]
        except KeyError:
            return {}


def toml2dn_policy(
    argv: list[str] | None = None,
    argconfname: str = "--conf_file",
    argsecname: str = "--policy-name",
    filename: str | None = None,
    section: str | None = None,
) -> dict[str, str]:
    return _get_toml_policy_data(argv, argconfname, argsecname, "dn", filename,section)

def toml2ext_policy( 
    argv: list[str] | None = None,
    argconfname: str = "--conf_file",
    argsecname: str = "--policy-name",
    filename: str | None = None,
    section: str | None = None,
) -> dict[str, str]:  # pragma: no cover, for future use
    """
    Loads extensions. Global 'policy.ext' is overwritten by 'policy.<section>.ext'.
    """
    return _get_toml_policy_data(argv, argconfname, argsecname, "ext", filename,section)

def toml2san_policy(
    argv: list[str] | None = None,
    argconfname: str = "--conf_file",
    argsecname: str = "--policy-name",
    filename: str | None = None,
    section: str | None = None,
) -> dict[str, str | int]:  # pragma: no cover, for future use
    """
    Loads SAN policy. Note: Validation logic currently not implemented.
    """
    return _get_toml_policy_data(argv, argconfname, argsecname, "san", filename, section)

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
    test_file = testfiles_dir / "get_started_toml_utils.rst"
    
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
