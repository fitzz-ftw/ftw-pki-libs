# File: src/ftwpki/baselibs/utils.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
utils
===============================


Modul utils documentation
"""
import sys
from pathlib import Path
from tomllib import TOMLDecodeError, loads


def toml2dn(argv: list[str]|None = None, argname: str = "--conf_file") -> dict[str, str]:
    if argv is None:
        argv = sys.argv[1:]
    try:
        index = argv.index(argname)
    except ValueError:
        return {}
    try:
        tomlfile=Path(argv[index+ 1])
        conf_str = tomlfile.read_text()
    except FileNotFoundError:
        print(f"File '{argv[index + 1]}' not found!")
        return {"dnsubject": ""}
    try:
        tomfile = loads(conf_str)
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
    test_file = testfiles_dir / "get_started_utils.rst"
    
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
