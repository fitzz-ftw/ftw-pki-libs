# File: src/ftwpki/baselibs/exceptions.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2.1
"""
PKI Custom Exceptions
=====================

This module defines the specialized exception hierarchy for the fitzzpki
namespace. It provides a structured way to handle security, encryption,
and validation errors consistently across the library. (ro)

Inheritance Summary:
    * PKIError (Base)
        * PKISecurityError
            * PKIEncryptionError
            * PKIValidationError
"""

from pathlib import Path


class PKIError(Exception):
    """
    Base class for all exceptions in the fitzzpki namespace. (ro)

    Catch Order:
        1. PKIError
        2. Exception
    """

    def __repr__(self) -> str:
        """
        Return a formal string representation of the error. (rw)

        :returns: String in the format 'ClassName()'.
        """
        return f"{self.__class__.__name__}()"


class PKISecurityError(PKIError):
    """
    Base error for security and cryptographic operations. (ro)

    Catch Order:
        1. PKISecurityError
        2. PKIError
        3. Exception
    """

    def __repr__(self) -> str:
        """
        Return a formal string representation of the security error. (rw)

        :returns: String in the format 'ClassName()'.
        """
        return f"{self.__class__.__name__}()"


class PKIEncryptionError(PKISecurityError):
    """
    Exception raised when an encryption operation fails. (ro)

    Common causes include invalid keys, malformed input data, or
    PKCS7 envelope failures.

    Catch Order:
        1. PKIEncryptionError
        2. PKISecurityError
        3. PKIError
        4. Exception
    """

    def __repr__(self) -> str:
        """
        Return a formal string representation of the encryption error. (rw)

        :returns: String in the format 'ClassName()'.
        """
        return f"{self.__class__.__name__}()"


class PKIValidationError(PKISecurityError):
    """
    Exception raised when certificate or policy validation fails. (rw)

    Catch Order:
        1. PKIValidationError
        2. PKISecurityError
        3. PKIError
        4. Exception
    """

    def __init__(self, dut: str, operation: str, orig: str) -> None:
        """
        Initialize the validation error with details about the mismatch. (rw)

        :param dut: The 'Device Under Test' or the value being checked.
        :param operation: The type of check performed (e.g., 'match').
        :param orig: The original reference value that caused the conflict.
        """
        msg = f"No match {dut} {operation} {orig}"
        super().__init__(msg)

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
