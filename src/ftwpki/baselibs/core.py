# File: src/ftwpki/baselibs/core.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2.1
"""
core
===============================


Modul core documentation
"""

import stat
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ftwpki.baselibs.exceptions import PKIEncryptionError


def generate_rsa_key_pair(passphrase: str, key_size: int = 4096) -> tuple[bytes, bytes]:
    """
    Generates a standard-compliant RSA key pair.

    Returns a tuple: (encrypted_private_key_pem, public_key_pem)
    The private key is encrypted using PKCS8 and BestAvailableEncryption.
    """

    # RSA Key-Objekt erzeugen
    private_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    # Verschlüsselungs-Algorithmus wählen
    if passphrase:
        encryption = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        encryption = serialization.NoEncryption()

    # Private Key -> PKCS#8 PEM (Standard)
    private_pem = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

    # Public Key -> SubjectPublicKeyInfo PEM (Standard)
    public_pem = private_key_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

def create_distinguished_name(
    common_name: str,
    country: str,
    state: str,
    location: str,
    organization: str,
    organizational_unit: str = ".",
    email_address: str = ".",
) -> x509.Name:
    """
    Create an X.509 Distinguished Name (DN) object.

    :param common_name: CN attribute
    :param country: C attribute (2 letters)
    :param state: ST attribute
    :param location: L attribute
    :param organization: O attribute
    :param organizational_unit: OU attribute (optional)
    :returns: x509.Name object
    """
    attributes = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, location),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
    ]

    if organizational_unit != ".":
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))

    if email_address != ".":
        attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address))

    attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))

    return x509.Name(attributes)

def save_pem(data: bytes, target_path: Path, is_private: bool = False) -> None:
    """
    Save PEM data to disk with appropriate permissions.

    :param data: The PEM encoded bytes.
    :param target_path: The file path to save to.
    :param is_private: If True, set restricted owner-only permissions (600).
    """
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_bytes(data)
    
    if is_private:
        target_path.chmod(stat.S_IREAD | stat.S_IWRITE)

def get_pem_bytes(item: x509.Certificate | x509.CertificateSigningRequest) -> bytes:
    """
    Convert a cryptography object to PEM encoded bytes.

    :param item: The certificate or CSR object.
    :returns: PEM encoded bytes.
    """
    return item.public_bytes(serialization.Encoding.PEM)

def create_chain_bytes(certificates: list[x509.Certificate]) -> bytes:
    """
    Combine multiple certificate objects into a single PEM byte string.

    :param certificates: List of certificate objects.
    :returns: Combined PEM bytes.
    """
    chain_data = b""
    for cert in certificates:
        chain_data += get_pem_bytes(cert)
    return chain_data

def load_private_key_from_pem(pem_data: bytes, passphrase: str) -> rsa.RSAPrivateKey:
    """
    Loads an encrypted RSA private key from PEM data (PKCS8).

    :param pem_data: The encrypted PEM bytes.
    :param passphrase: The password to decrypt the key.
    :return: An internal RSA private key object.
    :raises ValueError: If decryption fails or the key format is invalid.
    """
    try:

        key = serialization.load_pem_private_key(pem_data, 
                                            password=passphrase.encode() if passphrase else None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        # Wir mappen die Library-Fehler auf einen sauberen ValueError für die UI/Logik
        raise PKIEncryptionError("Could not decrypt or load the private key. Check your passphrase.") from e  # noqa: E501

    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("The provided key is not an RSA private key.")
    return key

def load_certificate_from_pem(pem_data: bytes) -> x509.Certificate:
    """
    Loads a PEM encoded certificate into a cryptography object.

    :param pem_data: The PEM encoded certificate bytes.
    :return: An x509.Certificate object.
    """
    return x509.load_pem_x509_certificate(pem_data)

def load_csr_from_pem(pem_data: bytes) -> x509.CertificateSigningRequest:
    """
    Loads a PEM encoded CSR into a cryptography object.
    """
    return x509.load_pem_x509_csr(pem_data)


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
    test_file = testfiles_dir / "get_started_core.rst"
    
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
