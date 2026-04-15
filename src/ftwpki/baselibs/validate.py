# File: src/ftwpki/baselibs/validate.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
validate
===============================


Modul validate documentation
"""

from pathlib import Path

from ftwpki.baselibs.exceptions import PKIValidationError


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

    def __init__(self, policy: dict[str, str], issuer_dn: dict[str, str]):
        """
        :param policy: Mapping of attribute names to validation modes.
        :param issuer_dn: The DN of the issuing CA (reference for 'match').
        """
        self._policy = policy
        self._issuer_dn = issuer_dn

    def validate(self, csr_dn: dict[str, str]) -> bool:
        """
        Check the CSR's Distinguished Name against the policy rules.
        
        Raises PKIValidationError if a rule is violated.
        """
        # Iterate over all attributes defined in policy or present in CSR
        all_keys = set(self._policy.keys()) | set(csr_dn.keys())
        
        for key in all_keys:
            mode = self._policy.get(key)
            csr_value = csr_dn.get(key, "")
            issuer_value = self._issuer_dn.get(key, "")

            # 1. DISALLOWED: Explizit verboten oder nicht in Policy definiert
            if mode in self.MODES_DISALLOWED:
                if csr_value:
                    raise PKIValidationError(dut=key, operation="DISALLOWED", orig="empty")

            # 2. MATCH: Muss identisch zum Issuer sein
            elif mode == self.MODE_MATCH:
                if csr_value != issuer_value:
                    raise PKIValidationError(
                        dut=f"{key}:{csr_value}", operation="MATCH", orig=issuer_value
                    )

            # 3. SUPPLIED: Muss im CSR vorhanden sein
            elif mode == self.MODE_SUPPLIED:
                if not csr_value:
                    raise PKIValidationError(dut=key, operation="SUPPLIED", orig="any_value")

            # 4. OPTIONAL: Vorhandensein egal, keine Prüfung
            elif mode == self.MODE_OPTIONAL:
                continue

            # 5. UNKNOWN MODE: Sicherheitsnetz für Tippfehler in der Policy
            else:
                raise PKIValidationError(
                    dut=key, operation="UNKNOWN_POLICY_MODE", orig=f"defined mode: {mode}"
                )
                
        return True

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._policy})"

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
