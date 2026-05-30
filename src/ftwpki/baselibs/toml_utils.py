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

from ftwpki.baselibs.app_dirs import config_file_path
from ftwpki.baselibs.exceptions import PKIFileNotFoundError, PKIKeyError


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

# FUNCTION - toml2dn_DEV
# DOC - change: raise TOMLDecodeError, PKIKeyError

def toml2dn_DEV(file_content: str ) -> dict[str, str]:
    """
    Extract distinguished name attributes from a TOML configuration file. (ro)

    This is the new standard implementation that operates directly on a
    file path, bypassing any global sys.argv context.

    :param file_name: The path or name of the TOML configuration file.
    :returns: A dictionary containing the distinguished name attributes.
    """
    try:
        tomfile = loads(file_content)
    except TOMLDecodeError:
        raise TOMLDecodeError("Could not decode file content!")
    try:
        dn = tomfile["identity"]["dn"]
    except KeyError:
        raise PKIKeyError("No table 'identity.dn' in config file!")
    dn["dnsubject"] = ""
    return dn


# !FUNCTION - toml2dn_DEV


# FUNCTION - toml2dn

# DOC - change: raise PKIFileNotFoundError, TOMLDecodeError, PKIKeyError
def toml2dn(file_name: str | Path| None) -> dict[str, str]:
    """
    Extract distinguished name attributes from a TOML configuration file. (ro)

    This is the new standard implementation that operates directly on a
    file path, bypassing any global sys.argv context.

    :param file_name: The path or name of the TOML configuration file.
    :returns: A dictionary containing the distinguished name attributes.
    """
    try:
        tomlfile = Path(file_name)
        conf_str = tomlfile.read_text()
        # tomfile = loads(conf_str)
    except FileNotFoundError:
        raise PKIFileNotFoundError(f"File '{tomlfile.name}' not found!")
    try:
        dn = toml2dn_DEV(conf_str)
    except TOMLDecodeError:
        raise TOMLDecodeError(f"Could not decode file {tomlfile.name}!")
    except PKIKeyError:
        raise PKIKeyError(f"No table 'identity.dn' in file {tomlfile.name}!")
    dn["dnsubject"] = ""
    return dn
# !FUNCTION - toml2dn


# FUNCTION - toml2_dn

def toml2_dn(argv: list[str] | None = None, argname: str = "--conf-file") -> dict[str, str]:
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
# !FUNCTION - toml2_dn

# FUNCTION - toml2dn_

# DOC - change: raise PKIFileNotFoundError, TOMLDecodeError, PKIKeyError
def toml2dn_(file_name: str | Path| None) -> dict[str, str]:
    """
    Extract distinguished name attributes from a TOML configuration file. (ro)

    This is the new standard implementation that operates directly on a
    file path, bypassing any global sys.argv context.

    :param file_name: The path or name of the TOML configuration file.
    :returns: A dictionary containing the distinguished name attributes.
    """
    try:
        tomlfile = Path(file_name)
        conf_str = tomlfile.read_text()
        tomfile = loads(conf_str)
    except FileNotFoundError:
        raise PKIFileNotFoundError(f"File '{tomlfile.name}' not found!")
    except TOMLDecodeError:
        raise TOMLDecodeError(f"Could not decode file {tomlfile.name}!")
        # print(f"Could not decode file {tomlfile.name}!")
        # return {"dnsubject": ""}
    try:
        dn = tomfile["identity"]["dn"]
    except KeyError:
        raise PKIKeyError("No table 'identity.dn' in config file!")
        # print("No table 'identity.dn' in config file!")
        # return {"dnsubject": ""}
    dn["dnsubject"] = ""
    return dn


# !FUNCTION - toml2_dn_

# FUNCTION - _get_toml_policy_data_DEV
def _get_toml_policy_data_DEV(policy_type: str, 
                              file_content: str, 
                              section: str | None) -> dict:
    """
    Find and load policy data from a TOML configuration file. (ro)

    This internal helper resolves the file path and section name either
    from direct arguments or command-line flags. It reads the TOML
    content and extracts specific policy information based on the
    provided type and section name.

    :param policy_type: The category of policy to extract.
    :param filename: Direct path to the TOML file, overrides argv.
    :param section: Direct section name, overrides argv.
    :raises OSError: If the file exists but cannot be read.
    :returns: A dictionary containing the requested policy data or
              an error indicator.
    """
    section_name = section

    try:
        data: dict[str, dict] = loads(file_content)
    except TOMLDecodeError:
        raise TOMLDecodeError("Could not decode file content!")

    data = data.get("policy", {})
    if not section_name:
        list_policy_sections(data, policy_type)
        return {"commonName": "error"}
    else:
        # section_name = cast(str, section_name)
        try:
            if policy_type == "ext":  # for future use
                extensions = data.get("ext", {}).copy()
                specific_ext = data.get(section_name, {}).get("ext", {})
                extensions.update(specific_ext)
                return extensions
            else:
                ret_data = data.get(policy_type, {})
                ret_data.update(data[section_name][policy_type])
                return ret_data  #!SECTION[section_name][policy_type]
        except KeyError:
            raise PKIKeyError(f"Key: {section_name}.{policy_type} not found.")
            


# !FUNCTION - _get_toml_policy_data_DEV


# FUNCTION - _get_toml_policy_data
def _get_toml_policy_data(policy_type:str,
                          filename: str,
                          section:str
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

    try:
        file_content = Path(filename).read_text()
    except FileNotFoundError:
        raise PKIFileNotFoundError(f"File '{filename}' not found!")

    try:
        data = _get_toml_policy_data_DEV(policy_type=policy_type,
                                         file_content=file_content,
                                         section=section)
    except TOMLDecodeError:
        raise TOMLDecodeError(f"Could not decode file {filename}!")
    return data

# !FUNCTION - _get_toml_policy_data

# FUNCTION - toml2ext
def toml2ext(filename: str | Path, section: str|None=None) -> dict[str, str]:
    """
    Extract X.509 extension attributes from a TOML configuration file. (ro)

    This is the new standard implementation operating directly on a
    file path and section name, bypassing legacy CLI argument parsing.

    :param file_name: The path or name of the TOML configuration file.
    :param policy_name: The specific section name of the extensions.
    :returns: A dictionary containing the extension attributes.
    """
    # Comments and docstrings are in simple English as requested.
    # Direct and clean call to the internal helper
    return _get_toml_policy_data("ext", filename=str(filename), section=section)

# !FUNCTION - toml2ext

# FUNCTION - toml2dn_policy_DEV
def toml2dn_policy_DEV(file_content: str, section: str|None=None) -> dict[str, str]:
    """
    Extract specific policy section data from a TOML configuration file. (ro)

    This is the temporary wrapper for the new standard implementation
    operating directly on a file path and section name.

    :param filename: The path or name of the TOML configuration file.
    :param policyname: The specific section name of the policy.
    :returns: A dictionary containing the policy attributes.
    """
    # Using the fake_argv array to bridge safely to the legacy parser
    return _get_toml_policy_data_DEV("dn", filename=file_content, section=section)

# !FUNCTION - toml2dn_policy_DEV

# FUNCTION - toml2dn_policy
def toml2dn_policy(filename: str | Path, section: str | None = None) -> dict[str, str]:
    """
    Extract specific policy section data from a TOML configuration file. (ro)

    This is the temporary wrapper for the new standard implementation
    operating directly on a file path and section name.

    :param filename: The path or name of the TOML configuration file.
    :param policyname: The specific section name of the policy.
    :returns: A dictionary containing the policy attributes.
    """
    # Using the fake_argv array to bridge safely to the legacy parser
    return _get_toml_policy_data("dn", filename=str(filename), section=section)


# !FUNCTION - toml2dn_policy


# FUNCTION - toml2ext_policy
def toml2ext_policy(filename: str | Path, section: str | None = None) -> dict[str, str]:
    """
    Extract extension policy attributes from a TOML configuration file. (ro)

    This is the temporary wrapper for the new standard implementation
    operating directly on a file path and section name.

    :param file_name: The path or name of the TOML configuration file.
    :param policy_name: The specific section name of the policy.
    :returns: A dictionary containing the extension attributes.
    """
    return _get_toml_policy_data("ext", filename=str(filename), section=section)

# !FUNCTION - toml2ext_policy


# FUNCTION - toml2san_policy
def toml2san_policy(filename: str | Path, section: str | None = None) -> dict[str, str]:
    """
    Extract Subject Alternative Name policy attributes from a TOML file. (ro)

    This is the temporary wrapper for the new standard implementation
    operating directly on a file path and section name.

    :param file_name: The path or name of the TOML configuration file.
    :param policy_name: The specific section name of the policy.
    :returns: A dictionary containing the SAN attributes.
    """
    return _get_toml_policy_data("san", filename=str(filename), section=section)

# !FUNCTION - toml2san_policy

# FUNCTION - toml2config
def toml2config(section:str="", file_name:str|None=None) -> dict[str,str]:
    """
    Load application configuration from a TOML file. (ro)

    This function reads the default configuration file. It starts with
    the base settings from the 'fallback' section and optionally
    overwrites them with values from a specific secondary section.

    :param section: The name of the additional configuration section
                    to load.
    :param file_name: The name of the configuration file.
    :raises FileNotFoundError: If the configuration file does not exist.
    :raises OSError: If the file cannot be opened or read.
    :returns: A dictionary containing the merged configuration settings.
    """
    conf_file = config_file_path(file_name=file_name)
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

