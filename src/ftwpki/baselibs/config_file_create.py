# File: src/ftwpki/baselibs/config_file_create.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
config_file_create
===============================


Modul config_file_create documentation
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


def write_example_config(content:str):
    conf_path = config_file_path()
    if conf_path.exists():
        return 
    if not conf_path.parent.exists():
        conf_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    conf_path.write_text(content+"\n")
    conf_path.chmod(0o600)



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


