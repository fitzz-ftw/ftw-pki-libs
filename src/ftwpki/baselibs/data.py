# File: src/ftwpki/baselibs/data.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
data
===============================


Modul data documentation
"""

from datetime import datetime
from pathlib import Path
from typing import Literal, NamedTuple

CertificateStatus = Literal["V", "R", "E"]
""" 
Define the allowed status types for a certificate.

V: Valid, R: Revoked, E: Expired
"""


class CertificateRecord(NamedTuple):
    """
    Immutable record for certificate metadata.
    Used for database logging and index.txt compatibility.
    """
    status: CertificateStatus 
    expiry: datetime
    revocation_date: str   # Format: YYMMDDHHMMSSZ,reason or empty
    serial: str            # Hexadecimal string
    subject: str  # Subject DN (RFC4514 format)
    filename: str = "unknown" # Usually 'unknown'

    @property
    def openssl_index_line(self) -> str:
        """
        Transcribes the record into the OpenSSL index.txt tab-separated format.
        """
        expiry_str = self.expiry.strftime("%y%m%d%H%M%SZ")
        if self.status == "R":
            return f"{self.status}\t{self.revocation_date}\t{expiry_str}\t{self.serial}\t{self.filename}\t{self.subject}"  # noqa: E501
        return f"{self.status}\t{expiry_str}\t{self.revocation_date}\t{self.serial}\t{self.filename}\t{self.subject}"  # noqa: E501

class ValidationError(NamedTuple):
    field: str
    message: str
    invalid_value: str = ""

    def __str__(self):
        """Schöne Formatierung für die Konsolenausgabe"""
        val_str = f" (Got: '{self.invalid_value}')" if self.invalid_value else ""
        return f"  - [{self.field}]: {self.message}{val_str}"


class ValidationResult(NamedTuple):
    is_valid: bool
    errors: list[ValidationError]


class ValidityDateCheckResult(NamedTuple):
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
