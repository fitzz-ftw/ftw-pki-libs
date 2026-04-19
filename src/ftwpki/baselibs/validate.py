# File: src/ftwpki/baselibs/validate.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
validate
===============================


Modul validate documentation
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509

from ftwpki.baselibs.data import ValidationError, ValidationResult, ValidityDateCheckResult
from ftwpki.baselibs.protocols import PolicyType


class ValidatorDN:
    """
    Validates Distinguished Name attributes of a CSR against a CA policy.
    
    The validation uses an issuer_dn as a reference for 'match' operations.
    """
    # Modes where an attribute is strictly forbidden
    MODES_DISALLOWED = {None, "none", "no", "not"}
    MODE_MATCH = "match"
    MODE_SUPPLIED = "supplied"
    MODE_OPTIONAL = "optional"

    def __init__(self, policy: dict[str, PolicyType], issuer_dn: dict[str, str]):
        """
        :param policy: Mapping of attribute names to validation modes.
        :param issuer_dn: The DN of the issuing CA (reference for 'match').
        """
        self._policy = policy
        self._issuer_dn = issuer_dn

    def validate(self, csr_dn: dict[str, str]) -> ValidationResult:
        """
        Check the CSR's Distinguished Name against the policy rules.
        
        Raises PKIValidationError if a rule is violated.
        """
        # Iterate over all attributes defined in policy or present in CSR
        all_keys = set(self._policy.keys()) | set(csr_dn.keys())
        errors = []
        for key in all_keys:
            mode = self._policy.get(key)
            csr_value = csr_dn.get(key, "")
            issuer_value = self._issuer_dn.get(key, "")

            # 1. DISALLOWED: Explizit verboten oder nicht in Policy definiert
            if mode in self.MODES_DISALLOWED:
                if csr_value:
                    errors.append(ValidationError(field=key, message="DISALLOWED"))
                    # raise PKIValidationError(dut=key, operation="DISALLOWED", orig="empty")

            # 2. MATCH: Muss identisch zum Issuer sein
            elif mode == self.MODE_MATCH:
                if csr_value != issuer_value:
                    errors.append(
                        ValidationError(
                            field=f"{key}:{issuer_value}",
                            message="MATCH",
                            invalid_value=csr_value
                        )
                    )
                    # raise PKIValidationError(
                    #     dut=f"{key}:{csr_value}", operation="MATCH", orig=issuer_value
                    # )

            # 3. SUPPLIED: Muss im CSR vorhanden sein
            elif mode == self.MODE_SUPPLIED:
                if not csr_value:
                    errors.append(ValidationError(field=key, message="SUPPLIED"))
                    # raise PKIValidationError(dut=key, operation="SUPPLIED", orig="any_value")

            # 4. OPTIONAL: Vorhandensein egal, keine Prüfung
            elif mode == self.MODE_OPTIONAL:
                continue

            # 5. UNKNOWN MODE: Sicherheitsnetz für Tippfehler in der Policy
            else:
                errors.append(ValidationError(field=key, 
                                              message="UNKNOWN_POLICY_MODE",
                                              invalid_value=str(mode)))
                # raise PKIValidationError(
                #     dut=key, operation="UNKNOWN_POLICY_MODE", orig=f"defined mode: {mode}"
                # )
        if errors:
            return ValidationResult(False, errors)
        else:
            return ValidationResult(True, [])

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._policy})"


def validate_and_clamp_validity(ca_cert:x509.Certificate, 
                                requested_days: int) -> ValidityDateCheckResult:
    # Direkter Zugriff auf die Property der cryptography-Library
    ca_not_after = ca_cert.not_valid_after_utc
    now = datetime.now(timezone.utc)
    requested_not_after = now + timedelta(days=requested_days)
    
    is_shortened = False
    final_not_after = requested_not_after
    
    if requested_not_after > ca_not_after:
        final_not_after = ca_not_after
        is_shortened = True
    
    # Berechne die tatsächlichen Tage (abgerundet)
    actual_delta = final_not_after - now
    actual_days = actual_delta.days
    
    return ValidityDateCheckResult(
        not_after=final_not_after,
        is_shortened=is_shortened,
        original_requested_days=requested_days,
        actual_days=actual_days
    )

def validate_uri(uri: str, no_https: bool = False, uri_type: str = ""):
    allowed_schemes = ["http", "https"]
    try:
        url_candidate = uri.split("URI:")[-1].strip()
        
        if not url_candidate:
            return ""

        parsed = urlparse(url_candidate)

        # 1. Validitäts-Check (Schema und Host müssen da sein)
        if not all([parsed.scheme, parsed.netloc]):
            print(f"Warning: '{url_candidate}' is not a valid absolute URL.")
            return ""

        # --- AB HIER: Checks für valide URLs ---

        # 2. Endlosschleifen-Prävention: HTTPS verbieten (z.B. für OCSP)
        if no_https and parsed.scheme.lower() == "https":
            msg = "OCSP URI must be HTTP" if uri_type.lower() == "oscp" else "Must be HTTP"
            msg = "CRL URI mut be HTTP" if uri_type.lower()== "crl" else msg
            print(f"Error: {msg} to avoid circular dependencies! Skipping: {url_candidate}")
            return ""

        # 3. Scheme-Check (Nur http/https erlauben)
        if parsed.scheme.lower() not in allowed_schemes:
            print(f"Warning: URI scheme '{parsed.scheme}' is unusual. Skipping: {url_candidate}")
            return ""

        return url_candidate

    except Exception as e:
        print(f"Warning: Could not process URI '{uri}': {e}")
        return ""


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
