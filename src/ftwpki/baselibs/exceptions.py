# File: src/ftwpki/baselibs/exceptions.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2.1
"""
exceptions
===============================


Modul exceptions documentation
"""

from pathlib import Path


class PKIError(Exception):
    """
    Base class for all exceptions in the fitzzpki namespace.

    Catch Order: 
        * PKIError
        * Exception
    """

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"

class PKISecurityError(PKIError):
    """
    Base error for security and cryptographic operations.

    Catch Order: 
        * PKISecurityError
        * PKIError
        * Exception
    """
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"

class PKIEncryptionError(PKISecurityError):
    """
    Raised when an encryption operation fails.

    Catch Order: 
        * PKIEncryptionError
        * PKISecurityError
        * PKIError
        * Exception
    """
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"



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
    test_file = testfiles_dir / "get_started_exceptions.rst"
    
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
