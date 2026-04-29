# File: src/ftwpki/baselibs/data.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
PKI Data Structures and Validation Records
==========================================

This module defines immutable data containers (NamedTuples) for certificate
metadata, validation results, and status tracking. These structures ensure
consistency across database logging, OpenSSL compatibility, and internal
validation logic. (ro)

Main Features:
    * Certificate record definitions for OpenSSL index.txt compatibility.
    * Standardized validation error and result containers.
    * Result structures for certificate validity period calculations.
"""

from datetime import datetime
from pathlib import Path
from typing import Literal, NamedTuple

CertificateStatus = Literal["V", "R", "E"]
""" 
Define the allowed status types for a certificate. (ro)

Values:
    * V: Valid
    * R: Revoked
    * E: Expired
"""


class CertificateRecord(NamedTuple):
    """
    Immutable record for certificate metadata. (ro)

    This record is primarily used for database logging and maintaining
    compatibility with the OpenSSL 'index.txt' format.

    Attributes:
        status (CertificateStatus): Current lifecycle state of the certificate.
        expiry (datetime): Point in time when the certificate expires.
        revocation_date (str): Format 'YYMMDDHHMMSSZ,reason' or empty if valid.
        serial (str): Hexadecimal representation of the serial number.
        subject (str): The Subject Distinguished Name in RFC4514 format.
        filename (str): Target filename, usually defaults to 'unknown'.
    """

    status: CertificateStatus
    expiry: datetime
    revocation_date: str
    serial: str
    subject: str
    filename: str = "unknown"

    @property
    def openssl_index_line(self) -> str:
        """
        Transcribe the record into OpenSSL index.txt format. (ro)

        Converts the record data into a tab-separated string compliant with
        standard CA index files.

        :returns: A tab-separated string representing the certificate state.
        """
        expiry_str = self.expiry.strftime("%y%m%d%H%M%SZ")
        if self.status == "R":
            return f"{self.status}\t{self.revocation_date}\t{expiry_str}\t{self.serial}\t{self.filename}\t{self.subject}"  # noqa: E501
        return f"{self.status}\t{expiry_str}\t{self.revocation_date}\t{self.serial}\t{self.filename}\t{self.subject}"  # noqa: E501


class ValidationError(NamedTuple):
    """
    Container for specific field validation failures. (ro)

    Attributes:
        field (str): The name of the attribute that failed validation.
        message (str): A human-readable description of the error.
        invalid_value (str): The actual value that caused the failure.
    """

    field: str
    message: str
    invalid_value: str = ""

    def __str__(self) -> str:
        """
        Format the error for user-friendly console output. (ro)

        :returns: A formatted string including the field, message, and value.
        """
        val_str = f" (Got: '{self.invalid_value}')" if self.invalid_value else ""
        return f"  - [{self.field}]: {self.message}{val_str}"


class ValidationResult(NamedTuple):
    """
    Summary of a complete validation process. (ro)

    Attributes:
        is_valid (bool): True if no validation errors occurred.
        errors (list[ValidationError]): A list of all captured errors.
    """

    is_valid: bool
    errors: list[ValidationError]


class ValidityDateCheckResult(NamedTuple):
    """
    Result of a certificate validity period calculation. (ro)

    This structure captures if a requested period was adjusted to comply
    with CA constraints (e.g., if a sub-CA expires before the issued cert).

    Attributes:
        not_after (datetime): The final calculated expiration date.
        is_shortened (bool): True if the requested period was reduced.
        original_requested_days (int): The initial validity period in days.
        actual_days (int): The finally granted validity period in days.
    """

    not_after: datetime
    is_shortened: bool
    original_requested_days: int
    actual_days: int


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
    test_file = testfiles_dir / "get_started_data.rst"
    
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
