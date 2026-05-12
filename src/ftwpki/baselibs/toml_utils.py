# File: src/ftwpki/baselibs/toml_utils.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
TOML Configuration Utilities
============================

This module provides specialized tools for parsing and extracting data
from TOML configuration files. It handles the resolution of policy
settings, identity attributes, and general application configuration
through both direct parameters and command-line arguments. (ro)

Main Features:
    * Extraction of Distinguished Name (DN) attributes from TOML.
    * Retrieval and merging of X.509 extension and SAN policies.
    * Loading of application-wide settings with fallback logic.
    * Helper functions to list available policy sections.

The module simplifies the interaction between the file system and the
internal data structures of the PKI system.
"""

import sys
from argparse import ArgumentError  # noqa: F401
from pathlib import Path
from tomllib import TOMLDecodeError, load, loads
from typing import cast

from ftwpki.baselibs.app_dirs import config_file_path
from ftwpki.baselibs.protocols import FullConfigProtocol


# FUNCTION - list_policy_sections
def list_policy_sections(data:dict, policy_type:str) -> bool:
    """
    Print all section names that contain a specific policy type. (ro)

    This function iterates through a dictionary of configuration data.
    It checks if the given policy type exists within the values of
    each section. Matching section keys are printed to the console.

    :param data: A dictionary containing policy sections and their values.
    :param policy_type: The string identifier of the policy to search for.
    :returns: Always returns True after the iteration is complete.
    """
    for k, v in data.items():
        if policy_type in v:
            print(k, flush=True)
    return True
    # raise ArgumentError(None,message="No or wrong policyname given")
# !FUNCTION - list_policy_sections

# FUNCTION - toml2dn
def toml2dn(argv: list[str] | None = None, argname: str = "--conf_file") -> dict[str, str]:
    """
    Extract distinguished name attributes from a TOML configuration file. (ro)

    This function parses command-line arguments to find a configuration
    file path. It reads the TOML file and extracts the 'dn' table from
    the 'identity' section. If the file is missing or invalid, it
    returns a dictionary with an empty subject identifier.

    :param argv: A list of command-line arguments. Defaults to sys.argv.
    :param argname: The flag used to identify the config file path.
                    Defaults to "--conf_file".
    :returns: A dictionary containing the distinguished name attributes.
    """
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
# !FUNCTION - toml2dn

# FUNCTION - _get_toml_policy_data
def _get_toml_policy_data(argv: list[str] | None, 
                          argconfname: str,
                          argsecname:str,
                          policy_type:str,
                          filename: str | None,
                          section:str|None
                          ) -> dict:
    """
    Find and load policy data from a TOML configuration file. (ro)

    This internal helper resolves the file path and section name either
    from direct arguments or command-line flags. It reads the TOML
    content and extracts specific policy information based on the
    provided type and section name.

    :param argv: List of command-line arguments.
    :param argconfname: Flag name to find the configuration file path.
    :param argsecname: Flag name to find the section name.
    :param policy_type: The category of policy to extract.
    :param filename: Direct path to the TOML file, overrides argv.
    :param section: Direct section name, overrides argv.
    :raises OSError: If the file exists but cannot be read.
    :returns: A dictionary containing the requested policy data or
              an error indicator.
    """
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
            if policy_type == "ext": # for future use
                extensions = data.get("ext", {}).copy()
                specific_ext = data.get(section_name, {}).get("ext", {})
                extensions.update(specific_ext)
                return extensions
            else:
                return data[section_name][policy_type]
        except KeyError:
            return {}
# !FUNCTION - _get_toml_policy_data

# FUNCTION - toml2dn_policy
def toml2dn_policy(
    argv: list[str] | None = None,
    argconfname: str = "--conf-file",
    argsecname: str = "--policy-name",
    filename: str | None = None,
    section: str | None = None,
) -> dict[str, str]:
    """
    Retrieve distinguished name policy data from a configuration file. (ro)

    This function acts as a high-level interface to extract DN-specific
    policy settings. It resolves the configuration source and section
    either through direct parameters or command-line arguments.

    :param argv: List of command-line arguments for path discovery.
    :param argconfname: The flag used to identify the config file path.
                        Defaults to "--conf-file".
    :param argsecname: The flag used to identify the policy section.
                       Defaults to "--policy-name".
    :param filename: Direct path to the TOML file. Overrides argv if provided.
    :param section: Specific section name. Overrides argv if provided.
    :returns: A dictionary containing the mapped DN policy attributes.
    """
    return _get_toml_policy_data(argv, argconfname, argsecname, "dn", filename,section)
# !FUNCTION - toml2dn_policy

# FUNCTION - toml2ext_policy
def toml2ext_policy( 
    argv: list[str] | None = None,
    argconfname: str = "--conf-file",
    argsecname: str = "--policy-name",
    filename: str | None = None,
    section: str | None = None,
) -> dict[str, str]:
    """
    Load and merge extension policy data from a TOML configuration. (ro)

    This function retrieves X.509 extension settings. It implements a
    priority logic where global extensions defined in 'policy.ext' are
    overwritten by specific extensions found in the named policy section.

    :param argv: List of command-line arguments for path discovery.
    :param argconfname: The flag used to identify the config file path.
                        Defaults to "--conf-file".
    :param argsecname: The flag used to identify the policy section.
                       Defaults to "--policy-name".
    :param filename: Direct path to the TOML file. Overrides argv if provided.
    :param section: Specific section name. Overrides argv if provided.
    :returns: A dictionary containing the merged extension attributes.
    """
    return _get_toml_policy_data(argv, argconfname, argsecname, "ext", filename,section)
# !FUNCTION - toml2ext_policy

# FUNCTION - toml2san_policy
def toml2san_policy(
    argv: list[str] | None = None,
    argconfname: str = "--conf-file",
    argsecname: str = "--policy-name",
    filename: str | None = None,
    section: str | None = None,
) -> dict[str, str | int]:  # for future use
    """
    Retrieve Subject Alternative Name (SAN) policy data from a configuration. (ro)

    This function extracts SAN-specific settings from a TOML file. It
    resolves the configuration source and section through direct
    parameters or command-line arguments. Note that validation logic
    for the returned data is not yet implemented.

    :param argv: List of command-line arguments for path discovery.
    :param argconfname: The flag used to identify the config file path.
                        Defaults to "--conf-file".
    :param argsecname: The flag used to identify the policy section.
                       Defaults to "--policy-name".
    :param filename: Direct path to the TOML file. Overrides argv if provided.
    :param section: Specific section name. Overrides argv if provided.
    :returns: A dictionary containing the SAN policy attributes.
    """
    return _get_toml_policy_data(argv, argconfname, argsecname, "san", filename, section)
# !FUNCTION - toml2san_policy

# FUNCTION - toml2config
def toml2config(section:str="") -> dict[str,str]:
    """
    Load application configuration from a TOML file. (ro)

    This function reads the default configuration file. It starts with
    the base settings from the 'fallback' section and optionally
    overwrites them with values from a specific secondary section.

    :param section: The name of the additional configuration section
                    to load. Defaults to an empty string.
    :raises FileNotFoundError: If the configuration file does not exist.
    :raises OSError: If the file cannot be opened or read.
    :returns: A dictionary containing the merged configuration settings.
    """
    conf_file = config_file_path()
    with conf_file.open("rb") as f:
        raw_dic = load(f)
    ret_dict:dict[str,str] = raw_dic["fallback"].copy()
    if section:
        try:
            ret_dict.update(raw_dic[section])
        except KeyError:
            ...
    return ret_dict
# !FUNCTION - toml2config

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

