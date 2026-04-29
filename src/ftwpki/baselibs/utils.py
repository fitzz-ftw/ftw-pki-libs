# File: src/ftwpki/baselibs/utils.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
General PKI Utilities
=====================

This module provides auxiliary functions for certificate validation and
human-readable data formatting. It contains tools to inspect X.509
extensions and generate text summaries of certificate data. (ro)

Main Features:
    * Validation of PEM certificate byte data.
    * Formatting of complex X.509 extensions into readable strings.
    * Generation of certificate summaries similar to OpenSSL text output.

These utilities are primarily used for logging, debugging, and user
interfaces.
"""

from pathlib import Path
from typing import LiteralString

from cryptography import x509


# FUNCTION - assert_is_pem_cert
def assert_is_pem_cert(data: bytes, name: str="Unknown") -> None:
    """
    Check if a byte object contains a valid PEM encoded certificate. (ro)

    This function acts as a gatekeeper. It verifies that the input data
    is of the correct byte type and attempts to parse it as an X.509
    certificate. If the data is invalid or of the wrong type, it raises
    an error.

    :param data: The byte sequence to be validated.
    :param name: A descriptive label for the data used in error messages.
                 Defaults to "Unknown".
    :raises TypeError: If the input data is not a byte string.
    :raises ValueError: If the data cannot be parsed as a valid PEM
                        certificate.
    """
    
    if not isinstance(data, bytes):
        raise TypeError(f"'{name}' muss vom Typ 'bytes' sein, nicht {type(data).__name__}.")

    try:
        # Der ultimative Test von cryptography
        x509.load_pem_x509_certificate(data.strip())
    except Exception as e:
        raise ValueError(f"'{name}' ist kein gültiges PEM-Zertifikat: {e}")
# !FUNCTION - assert_is_pem_cert

#FUNCTION - format_extension
def format_extension(ext, indent:int=0) -> str | LiteralString:
    """
    Format an X.509 extension into a human-readable string. (ro)

    This function identifies the type of the extension and extracts its
    values. It supports various types like Basic Constraints, Key Usage,
    and Authority Key Identifiers. The output is formatted with a
    specified indentation level for better readability.

    :param ext: The extension object to be formatted.
    :param indent: The number of indentation levels to apply. Defaults to 0.
    :raises AttributeError: If the extension lacks expected internal
                            attributes during processing.
    :returns: A formatted string representation of the extension and
              its attributes.
    """
    val = ext.value
    name = ext.oid._name
    inden:str = " "*4*indent

    if isinstance(val, x509.BasicConstraints):
        return (
            f"{inden}{name}:\n{inden*2} CA={'Yes' if val.ca else 'No'}, "
            f"path_length={val.path_length}"
        )

    if isinstance(val, x509.KeyUsage):
        # Wir definieren die Liste explizit, um die ValueError-Falle zu umgehen
        potential_usages = [
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
        ]

        # Sonderbehandlung für die "Agreement"-Abhängigkeiten
        if val.key_agreement:
            potential_usages.extend(["encipher_only", "decipher_only"])

        usages = [attr for attr in potential_usages if getattr(val, attr)]
        used = ", ".join(usages)
        return f"{inden}{name}:\n{inden * 2} {used}"



    if hasattr(val,"_usages"):
        ret_val = ", ".join([item._name for item in val._usages])
        return f"{inden}{name}:\n{inden * 2} {ret_val}"

    if name=="authorityKeyIdentifier":
        return f"{inden}{name}:\n{inden * 2} {val.key_identifier}"

    if hasattr(val, "_descriptions"):
        ret_val = f"\n{inden*2} ".join(
            [
                ": ".join((use.access_method._name, use.access_location.value))
                for use in val._descriptions
            ]
        )
        return f"{inden}{name}:\n{inden * 2} {ret_val}"
        

    if name == "cRLDistributionPoints":
        ret_val = f"\n{inden * 2}".join(
            [item.value for use in val._distribution_points for item in use.full_name]
        )
        return f"{inden}{name}:\n{inden * 2} {ret_val}"
        
    if name== "subjectKeyIdentifier":
        return f"{inden}{name}:\n{inden * 2} {val.digest}"

    return f"{name}: {val}"
# !FUNCTION - format_extension

# FUNCTION - get_cert_text
def get_cert_text(pem_path: str) -> str:
    """
    Return a human-readable summary of a certificate file. (ro)

    This function reads a certificate from the disk and extracts its
    core metadata. It provides a text representation of the subject,
    issuer, validity dates, and all included extensions, similar to
    the OpenSSL text output.

    :param pem_path: The file system path to the PEM encoded certificate.
    :raises FileNotFoundError: If the specified certificate file does not exist.
    :raises ValueError: If the file content is not a valid PEM certificate.
    :returns: A formatted multi-line string containing the certificate details.
    """
    cert_bytes = Path(pem_path).read_bytes()
    cert = x509.load_pem_x509_certificate(cert_bytes)

    lines = [
        f"Subject:\n\t {cert.subject.rfc4514_string()}",
        f"Issuer:\n\t {cert.issuer.rfc4514_string()}",
        f"Serial Number:\n\t {cert.serial_number}",
        f"Not Before:\n\t {cert.not_valid_before_utc}",
        f"Not After:\n\t {cert.not_valid_after_utc}",
        f"Version:\n\t {cert.version.name}",
    ]

    # Extensions hinzufügen (ähnlich wie OpenSSL)
    lines.append("Extensions:")
    for ext in cert.extensions:
        # lines.append(f"    {ext.oid._name}: {ext.value}")
        lines.append(format_extension(ext, indent=1))

    return "\n".join(lines)
# !FUNCTION - get_cert_text

# FUNCTION - get_cert_text_from_cert
def get_cert_text_from_cert(pem_bytes: bytes) -> str:
    """
    Return a human-readable summary from a certificate object. (ro)

    This function extracts core metadata from an existing X.509
    certificate object and formats it into a text summary. It includes
    details about the subject, issuer, validity period, and all
    certificate extensions.

    :param cert: The certificate object to be processed.
    :raises AttributeError: If the provided object is missing required
                            X.509 attributes.
    :returns: A formatted multi-line string containing the certificate
              information.
    """
    # cert_bytes = pem_bytes
    # cert = x509.load_pem_x509_certificate(cert_bytes)
    cert=pem_bytes

    lines = [
        f"Subject:\n\t {cert.subject.rfc4514_string()}",
        f"Issuer:\n\t {cert.issuer.rfc4514_string()}",
        f"Serial Number:\n\t {cert.serial_number}",
        f"Not Before:\n\t {cert.not_valid_before_utc}",
        f"Not After:\n\t {cert.not_valid_after_utc}",
        f"Version:\n\t {cert.version.name}",
    ]

    # Extensions hinzufügen (ähnlich wie OpenSSL)
    lines.append("Extensions:")
    for ext in cert.extensions:
        # lines.append(f"    {ext.oid._name}: {ext.value}")
        lines.append(format_extension(ext, indent=1))

    return "\n".join(lines)
# !FUNCTION - get_cert_text_from_cert


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
