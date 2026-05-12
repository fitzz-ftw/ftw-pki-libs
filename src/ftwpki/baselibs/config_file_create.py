# File: src/ftwpki/baselibs/config_file_create.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
Configuration File Creation
===========================

This module manages the creation of default configuration files for the
PKI application. It provides templates and functions to initialize the
system settings with secure file permissions. (rw)

Main Features:
    * Definition of TOML configuration templates for different PKI tiers.
    * Automatic creation of configuration directories.
    * Secure writing of initial configuration files with owner-only access.

The module ensures that the application has a valid starting point if no
configuration is present.
"""

from pathlib import Path

from ftwpki.baselibs.app_dirs import config_file_path

conf_toml = """
[fallback]
# Identität (verschlüsselt & versteckt)
private_keys = "{private_keys}"
passphrases  = "{passphrases}"

# Infrastruktur-Ressourcen (könnten später URLs werden)
csr_configs  = "{csr_configs}"
policies     = "{policies}"

# Öffentliche Daten (Standards zur einfachen Nutzung)
public_data  = "{public_data}"
certs        = "{certs}"
chains       = "{chains}"

# Dateiendungen nur für öffentliche/halbprivat Daten
ext_cert     = "{ext_cert}"
ext_public   = "{ext_public}"
ext_chain    = "{ext_chain}"
ext_csr_conf = "{ext_csr_conf}"
ext_policy   = "{ext_policy}"
ext_signedcert= "{ext_signedcert}"

[intermediate]
# Überschreibt bei Bedarf die Pfade für Intermediate-spezifische Regeln
policies     = "{intermediate_policies}"
"""

toml_conf_str = """
[fallback]
# Identität (verschlüsselt & versteckt)
private_keys = "~/.config/ftwpki/.private"
passphrases  = "~/.config/ftwpki/.private"

# Infrastruktur-Ressourcen (könnten später URLs werden)
csr_configs  = "~/.config/ftwpki/csr"
policies     = "~/.config/ftwpki/policies"

# Öffentliche Daten (Standards zur einfachen Nutzung)
public_data  = "~/.local/share/ftwpki"
certs        = "~/.local/share/ftwpki/certs"
chains       = "~/.local/share/ftwpki/chains"

# Dateiendungen nur für öffentliche/halbprivat Daten
ext_cert     = ".crt"
ext_public   = ".pub"
ext_chain    = ".pem"
ext_csr_conf = ".toml"
ext_policy   = ".policy"
ext_signedcert= ".zip.enc"

[intermediate]
# Überschreibt bei Bedarf die Pfade für Intermediate-spezifische Regeln
policies     = "~/.config/ftwpki/policies/intermediate"
"""

USER_CONFIG = """[fallback]
private_keys = "~/.config/ftwpki/.private"
public_data  = "~/.local/share/ftwpki"
certs        = "~/.local/share/ftwpki/certs"
chains       = "~/.local/share/ftwpki/chains"

ext_cert     = ".crt"
ext_public   = ".pub"
ext_signedcert= ".zip.enc"
"""

LEAF_CONFIG = """[fallback]
private_keys = "~/.config/ftwpki/.private"
public_data  = "~/.local/share/ftwpki"
certs        = "~/.local/share/ftwpki/certs"
chains       = "~/.local/share/ftwpki/chains"

ext_cert     = ".crt"
ext_public   = ".pub"
ext_signedcert= ".zip.enc"
"""

INTERMED_CONFIG = """[fallback]
private_keys = "~/.config/ftwpki/.private"
passphrases  = "~/.config/ftwpki/.private"


policies     = "~/.config/ftwpki/policies"


public_data  = "~/.local/share/ftwpki"
certs        = "~/.local/share/ftwpki/certs"
chains       = "~/.local/share/ftwpki/chains"

ext_cert     = ".crt"
ext_public   = ".pub"
ext_chain    = ".pem"
ext_policy   = ".policy"
ext_signedcert= ".zip.enc"

"""

ROOT_SIGNER_CONFIG = """[fallback]
private_keys = "~/.config/ftwpki/.private"
passphrases  = "~/.config/ftwpki/.private"

public_data  = "~/.local/share/ftwpki"
certs        = "~/.local/share/ftwpki/certs"
chains       = "~/.local/share/ftwpki/chains"

ext_cert     = ".crt"
ext_public   = ".pub"
ext_chain    = ".chain.pem"

"""

# FUNCTION - write_example_config
def write_example_config(content:str) -> None:
    """
    Write a sample configuration file to the default path. (rw)

    This function creates a configuration file with the provided content
    if it does not exist. It ensures the parent directory is created
    with restricted permissions and sets the file access to owner-only.

    :param content: The string content to be written into the config file.
    :raises OSError: If the directory cannot be created or the file
                     cannot be written.
    :raises PermissionError: If there are insufficient rights to set
                             file permissions.
    """
    conf_path = config_file_path()
    if conf_path.exists():
        return 
    if not conf_path.parent.exists():
        conf_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    conf_path.write_text(content+"\n")
    conf_path.chmod(0o600)
# !FUNCTION - write_example_config


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
    test_file = testfiles_dir / "get_started_config_file_create.rst"
    
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


