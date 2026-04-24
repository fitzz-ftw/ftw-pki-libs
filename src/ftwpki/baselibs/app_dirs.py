# File: src/ftwpki/baselibs/app_dirs.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
app_dirs
===============================


Modul app_dirs documentation
"""

from pathlib import Path

from platformdirs import PlatformDirs

# Die Instanz wird sofort beim ersten Import des Moduls erstellt (Eager)
_pki_dirs_instance = PlatformDirs(
    appname="ftwpki",
    appauthor="FitzzTeXnikWelt"
)

def PKIDirs() -> PlatformDirs:
    """
    Gibt die bereits beim Import erstellte PlatformDirs-Instanz zurück.
    So bleibt der Zugriff konsistent und zentral.
    """
    return _pki_dirs_instance

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
    test_file = testfiles_dir / "get_started_app_dirs.rst"
    
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
