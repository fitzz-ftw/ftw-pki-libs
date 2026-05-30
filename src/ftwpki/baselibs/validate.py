# File: src/ftwpki/baselibs/validate.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
validate
===============================

This module provides validation logic for Distinguished Names, certificate
validity periods, and URI formatting. (rw)
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509

from ftwpki.baselibs.data import ValidationError, ValidationResult, ValidityDateCheckResult
from ftwpki.baselibs.exceptions import PKIPolicyValidationError
from ftwpki.baselibs.protocols import PolicyType


class ValidatorDN:
    """
    Validates Distinguished Name attributes of a CSR against a CA policy. (rw)

    The validation uses an issuer_dn as a reference for 'match' operations.
    """

    # Modes where an attribute is strictly forbidden
    MODES_DISALLOWED = {None, "none", "no", "not"}
    MODE_MATCH = "match"
    MODE_SUPPLIED = "supplied"
    MODE_OPTIONAL = "optional"

    def __init__(self, policy: dict[str, PolicyType], issuer_dn: dict[str, str]):
        """
        Initialize the DN validator. (rw)

        :param policy: Mapping of attribute names to validation modes.
        :param issuer_dn: The DN of the issuing CA (reference for 'match').
        """
        self._policy = policy
        self._issuer_dn = issuer_dn

    def validate(self, csr_dn: dict[str, str], raise_on_error:bool=True) -> ValidationResult:
        """
        Check the CSR's Distinguished Name against the policy rules. (ro)

        :param csr_dn: The Distinguished Name from the CSR.
        :returns: A ValidationResult containing success status and error list.
        """
        # [Logik unverändert übernommen]
        all_keys = set(self._policy.keys()) | set(csr_dn.keys())
        errors = []
        for key in all_keys:
            mode = self._policy.get(key)
            csr_value = csr_dn.get(key, "")
            issuer_value = self._issuer_dn.get(key, "")

            if mode in self.MODES_DISALLOWED:
                if csr_value:
                    errors.append(ValidationError(field=key, message="DISALLOWED"))
            elif mode == self.MODE_MATCH:
                if csr_value != issuer_value:
                    errors.append(
                        ValidationError(
                            field=f"{key}:{issuer_value}", message="MATCH", invalid_value=csr_value
                        )
                    )
            elif mode == self.MODE_SUPPLIED:
                if not csr_value:
                    errors.append(ValidationError(field=key, message="SUPPLIED"))
            elif mode == self.MODE_OPTIONAL:
                continue
            else:
                errors.append(
                    ValidationError(
                        field=key, message="UNKNOWN_POLICY_MODE", invalid_value=str(mode)
                    )
                )
        if errors:
            if raise_on_error:
                raise PKIPolicyValidationError(errors)
            return ValidationResult(False, errors)
        else:
            return ValidationResult(True, [])

    def __repr__(self) -> str:
        """Return the canonical string representation. (rw)"""
        return f"{self.__class__.__name__}({self._policy})"


def validate_and_clamp_validity(
    ca_cert: x509.Certificate, requested_days: int
) -> ValidityDateCheckResult:
    """
    Validate and restrict a requested validity period against a CA cert. (ro)

    Ensures the issued certificate does not expire after the issuing CA.

    :param ca_cert: The certificate of the issuer.
    :param requested_days: Desired validity in days.
    :returns: ValidityDateCheckResult with the clamped date and status.
    """
    ca_not_after = ca_cert.not_valid_after_utc
    now = datetime.now(timezone.utc)
    requested_not_after = now + timedelta(days=requested_days)

    is_shortened = False
    final_not_after = requested_not_after

    if requested_not_after > ca_not_after:
        final_not_after = ca_not_after
        is_shortened = True

    actual_delta = final_not_after - now
    actual_days = actual_delta.days

    return ValidityDateCheckResult(
        not_after=final_not_after,
        is_shortened=is_shortened,
        original_requested_days=requested_days,
        actual_days=actual_days,
    )


def validate_uri(uri: str, no_https: bool = False, uri_type: str = ""):
    """
    Validate and normalize a URI string for X.509 extensions. (ro)

    :param uri: The raw URI string (can include 'URI:' prefix).
    :param no_https: If True, rejects HTTPS schemes (prevents circularity).
    :param uri_type: Type label for error messages (e.g., 'ocsp', 'crl').
    :returns: Validated URI string or empty string on failure.
    """
    allowed_schemes = ["http", "https"]
    try:
        url_candidate = uri.split("URI:")[-1].strip()

        if not url_candidate:
            return ""

        parsed = urlparse(url_candidate)

        if not all([parsed.scheme, parsed.netloc]):
            print(f"Warning: '{url_candidate}' is not a valid absolute URL.")
            return ""

        if no_https and parsed.scheme.lower() == "https":
            msg = "OCSP URI must be HTTP" if uri_type.lower() == "oscp" else "Must be HTTP"
            msg = "CRL URI mut be HTTP" if uri_type.lower() == "crl" else msg
            print(f"Error: {msg} to avoid circular dependencies! Skipping: {url_candidate}")
            return ""

        if parsed.scheme.lower() not in allowed_schemes:
            print(f"Warning: URI scheme '{parsed.scheme}' is unusual. Skipping: {url_candidate}")
            return ""

        return url_candidate

    except Exception as e:
        print(f"Warning: Could not process URI '{uri}': {e}")
        return ""


if __name__ == "__main__":  # pragma: no cover
    from doctest import FAIL_FAST, testfile

    be_verbose = False
    be_verbose = True
    option_flags = 0
    option_flags = FAIL_FAST
    test_sum = 0
    test_failed = 0

    # Pfad zu den dokumentierenden Tests
    testfiles_dir = Path(__file__).parents[3] / "doc/source/devel"
    test_file = testfiles_dir / "get_started_validate.rst"

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
