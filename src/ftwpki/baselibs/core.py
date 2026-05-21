# File: src/ftwpki/baselibs/core.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2.1
"""
Core Cryptography Utilities
===========================

This module provides fundamental cryptographic operations for the PKI system.
It includes functions for key generation, certificate handling, and data
transformation between internal objects and PEM formats.

Main Features:
    * RSA key pair generation and management.
    * X.509 name and certificate object creation.
    * Loading and saving PEM encoded data with secure permissions.
    * Certificate Revocation List (CRL) generation.
    * Mapping certificate metadata to standardized records.

The module relies on the 'cryptography' library for secure implementation
of all cryptographic primitives.
"""

import datetime
import stat
from pathlib import Path
from typing import cast

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ftwpki.baselibs.data import CertificateRecord, CertificateStatus
from ftwpki.baselibs.exceptions import PKIEncryptionError


# FUNCTION - generate_rsa_key_pair
def generate_rsa_key_pair(passphrase: str|None, key_size: int = 4096) -> tuple[bytes, bytes]:
    """
    Generate a standard-compliant RSA key pair. (rw)

    The private key is secured using the PKCS8 format and the best available
    encryption method. The public key is exported using the
    SubjectPublicKeyInfo format.

    :param passphrase: The secret string used to encrypt the private key.
    :param key_size: The bit length of the RSA key. Defaults to 4096.
    :raises ValueError: If the key size is too short or invalid.
    :raises TypeError: If the passphrase is not a string.
    :returns: A tuple containing the encrypted private key and the
              public key, both in PEM format.
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
# !FUNCTION - generate_rsa_key_pair

# FUNCTION - create_distinguished_name
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
    Create an X.509 Distinguished Name object. (rw)

    This function builds a name object using standard identity attributes
    like country, organization, and common name. Optional fields like
    the organizational unit and email address are added if they are not
    set to a dot.

    :param common_name: The common name for the subject.
    :param country: The two-letter country code.
    :param state: The state or province name.
    :param location: The city or locality name.
    :param organization: The name of the organization.
    :param organizational_unit: The unit within the organization. Defaults to ".".
    :param email_address: The contact email address. Defaults to ".".
    :raises TypeError: If any attribute value is not a string.
    :raises ValueError: If the country code is not exactly two characters long.
    :returns: An identity object containing the provided attributes.
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
# !FUNCTION - create_distinguished_name

# FUNCTION - save_pem
def save_pem(data: bytes, target_path: Path, is_private: bool = False) -> None:
    """
    Save PEM encoded data to a file with specific permissions. (rw)

    The function ensures that the target directory exists before writing.
    If the data is marked as private, the file permissions are restricted
    to owner-read and owner-write only.

    :param data: The byte content in PEM format to be stored.
    :param target_path: The full file system path where the file is saved.
    :param is_private: A flag to enable strict file permissions (600). Defaults to False.
    :raises OSError: If the directory cannot be created or the file cannot be written.
    :raises PermissionError: If the process lacks the rights to change file permissions.
    """
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_bytes(data)
    
    if is_private:
        target_path.chmod(stat.S_IREAD | stat.S_IWRITE)
# !FUNCTION - save_pem

#FUNCTION - get_pem_bytes
def get_pem_bytes(item: x509.Certificate | x509.CertificateSigningRequest) -> bytes:
    """
    Convert a cryptography object to PEM encoded bytes. (ro)

    This function takes an X.509 certificate or a certificate signing
    request and transforms it into a byte string using PEM encoding.

    :param item: The certificate or CSR object to be converted.
    :raises AttributeError: If the object does not support PEM export.
    :returns: The content of the object as PEM encoded bytes.
    """
    return item.public_bytes(serialization.Encoding.PEM)
# !FUNCTION - get_pem_bytes

#FUNCTION - create_chain_bytes
def create_chain_bytes(certificates: list[x509.Certificate]) -> bytes:
    """
    Combine multiple certificate objects into a single PEM byte string. (ro)

    This function iterates through a list of X.509 certificates and
    joins their PEM representations into a single byte sequence. This
    is commonly used to create certificate chain files.

    :param certificates: A list of certificate objects to be joined.
    :raises AttributeError: If an item in the list is not a valid
                            certificate object.
    :returns: The combined data of all certificates as PEM encoded bytes.
    """
    chain_data = b""
    for cert in certificates:
        chain_data += get_pem_bytes(cert)
    return chain_data
# !FUNCTION - create_chain_bytes

# FUNCTION - load_private_key_from_pem
def load_private_key_from_pem(pem_data: bytes, passphrase: str|None) -> rsa.RSAPrivateKey:
    """
    Load an encrypted RSA private key from PEM data. (ro)

    This function reads a private key in PKCS8 format. It uses the
    provided passphrase to decrypt the data. If the key is not an
    RSA private key, an error is raised.

    :param pem_data: The encrypted byte content in PEM format.
    :param passphrase: The secret string used to decrypt the key.
    :raises PKIEncryptionError: If the decryption fails due to a wrong
                                passphrase or unsupported algorithm.
    :raises ValueError: If the loaded key is not of the type RSA.
    :returns: A private key object used for cryptographic operations.
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
# !FUNCTION - load_private_key_from_pem


# FUNCTION - load_certificate_from_pem
def load_certificate_from_pem(pem_data: bytes) -> x509.Certificate:
    """
    Load a PEM encoded certificate into a cryptography object. (ro)

    This function transforms a certificate from its PEM byte format into
    an internal object for further processing or inspection.

    :param pem_data: The byte content of the certificate in PEM format.
    :raises ValueError: If the PEM data is invalid or cannot be parsed.
    :raises TypeError: If the input is not a byte string.
    :returns: A certificate object used for cryptographic operations.
    """
    return x509.load_pem_x509_certificate(pem_data)
# !FUNCTION - load_certificate_from_pem


# FUNCTION - load_csr_from_pem
def load_csr_from_pem(pem_data: bytes) -> x509.CertificateSigningRequest:
    """
    Load a PEM encoded CSR into a cryptography object. (ro)

    This function transforms a certificate signing request from its PEM
    byte format into an internal object for further processing.

    :param pem_data: The byte content of the CSR in PEM format.
    :raises ValueError: If the PEM data is invalid or cannot be parsed.
    :raises TypeError: If the input is not a byte string.
    :returns: A CSR object used for cryptographic operations.
    """
    return x509.load_pem_x509_csr(pem_data)
# !FUNCTION - load_csr_from_pem


# FUNCTION - convert_pem_to_der
def convert_pem_to_der(pem_bytes: bytes, is_key: bool = False, password: str = "") -> bytes:
    """
    Convert PEM encoded data into DER binary format **(rw)**.

    :param pem_bytes: The input data in PEM format.
    :param is_key: Flag to indicate if the input is a private key.
    :param password: The password for encrypted private keys.
    :raises cryptography.exceptions.UnsupportedAlgorithm: If the key type is not supported.
    :raises cryptography.exceptions.InternalError: If the library fails during loading.
    :raises ValueError: If the password is wrong or the PEM data is invalid.
    :returns: The data converted into DER binary format.
    """
    if is_key:
        # Falls password leer ist (""), wird pw_bytes zu None für die Library
        pw_bytes = password.encode() if password else None
        
        key = serialization.load_pem_private_key(
            pem_bytes,
            password=pw_bytes
        )
        
        return key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        cert = x509.load_pem_x509_certificate(pem_bytes)
        return cert.public_bytes(serialization.Encoding.DER)

#!FUNCTION - convert_pem_to_der


# FUNCTION - create_csr_name
#DOC - change
def create_csr_name(*args: str, suffix:str=".csr") -> str:
    """
    Create a file name for a Certificate Signing Request. (ro)

    This function joins all provided string arguments with underscores
    and replaces spaces with hyphens. It appends the '.csr' extension
    to the final string.

    :param args: Multiple strings used to build the file name.
    :raises TypeError: If any of the provided arguments is not a string.
    :returns: A formatted string suitable for a CSR file name.
    """
    return "_".join(args).replace(" ", "-").replace(".","") + suffix
# !FUNCTION - create_csr_name


# FUNCTION - cert_to_record
def cert_to_record(cert: x509.Certificate, status: CertificateStatus = "V") -> CertificateRecord:
    """
    Convert an X.509 certificate object into a standardized record format. (ro)

    This function extracts key metadata from a certificate and returns
    a record suitable for database storage or indexing. It processes
    the status, expiry date, serial number, and subject string.

    :param cert: The certificate object to be converted.
    :param status: The validation status of the certificate. Defaults to "V".
    :raises AttributeError: If the certificate object is missing required attributes.
    :returns: A structured record containing the certificate information.
    """
    return CertificateRecord(
        status=cast(CertificateStatus,status.upper()),
        expiry=cert.not_valid_after_utc,
        revocation_date="",
        serial=format(cert.serial_number, "02X"),
        subject=cert.subject.rfc4514_string(),
    )
# !FUNCTION - cert_to_record


# FUNCTION - revoke_record
def revoke_record(record: CertificateRecord, reason: str = "") -> CertificateRecord:
    """
    Create a new certificate record with a revoked status. (ro)

    This function takes an existing record and returns a copy with the
    status set to 'R'. It adds a UTC timestamp and an optional reason
    to the revocation field.

    :param record: The existing valid certificate record.
    :param reason: The explanation for the revocation. Defaults to "".
    :raises AttributeError: If the record object is not a valid
                            CertificateRecord.
    :returns: A new record object with updated revocation data.
    """
    # Aktueller UTC-Zeitstempel im OpenSSL-Format: YYMMDDHHMMSSZ
    now = datetime.datetime.now(datetime.timezone.utc)
    rev_ts = now.strftime("%y%m%d%H%M%SZ")

    # Wenn ein Grund angegeben wurde, wird er mit Komma angehängt
    rev_field = f"{rev_ts},{reason}" if reason else rev_ts

    # Da CertificateRecord ein NamedTuple (immutable) ist, nutzen wir _replace
    return record._replace(status="R", revocation_date=rev_field)
# !FUNCTION - revoke_record


# FUNCTION - create_crl
def create_crl(
    revoked_records: list[CertificateRecord],
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    next_update_days: int = 30,
) -> x509.CertificateRevocationList:
    """
    Create a signed Certificate Revocation List from a list of records. (rw)

    This function builds a CRL by filtering records for a revoked status.
    It extracts revocation dates and reasons, adds them to a list
    builder, and signs the final object using the certificate authority
    private key and SHA512.

    :param revoked_records: A list of certificate data objects to check.
    :param ca_cert: The certificate of the issuing authority.
    :param ca_key: The private key used to sign the revocation list.
    :param next_update_days: The number of days until the next update. Defaults to 30.
    :raises ValueError: If the serial number or dates are in an invalid format.
    :raises AttributeError: If the CA key or certificate is incompatible.
    :raises Exception: If the signing process fails.
    :returns: A signed CRL object containing all revoked certificates.
    """
    OPENSSL_REASON_MAP = {
        "unspecified": "unspecified",
        "keyCompromise": "key_compromise",
        "CACompromise": "ca_compromise",
        "affiliationChanged": "affiliation_changed",
        "superseded": "superseded",
        "cessationOfOperation": "cessation_of_operation",
        "certificateHold": "certificate_hold",
        "privilegeWithdrawn": "privilege_withdrawn",
        "AACompromise": "aa_compromise",
    }
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = x509.CertificateRevocationListBuilder()

    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(now)
    builder = builder.next_update(now + datetime.timedelta(days=next_update_days))

    for record in revoked_records:
        # Nur Records im Status 'R' (Revoked) gehören in die CRL
        if record.status != "R":
            continue

        # Zerlege revocation_date (YYMMDDHHMMSSZ[,reason])
        parts = record.revocation_date.split(",")
        rev_date = datetime.datetime.strptime(parts[0], "%y%m%d%H%M%SZ").replace(
            tzinfo=datetime.timezone.utc
        )

        rev_builder = x509.RevokedCertificateBuilder()
        rev_builder = rev_builder.serial_number(int(record.serial, 16))
        rev_builder = rev_builder.revocation_date(rev_date)

        # Grund hinzufügen, falls vorhanden
        if len(parts) > 1 and parts[1]:
            try:
                reason_str = parts[1]
                attr_name = OPENSSL_REASON_MAP.get(reason_str, reason_str)

                reason_oid = getattr(x509.ReasonFlags, attr_name)
                rev_builder = rev_builder.add_extension(x509.CRLReason(reason_oid), critical=False)
            except AttributeError:
                pass  # Unbekannte Gründe ignorieren

        builder = builder.add_revoked_certificate(rev_builder.build())

    return builder.sign(ca_key, hashes.SHA512())
# !FUNCTION - create_crl


# FUNCTION - get_subject_dict
def get_subject_dict(item: x509.Certificate | x509.CertificateSigningRequest) -> dict[str, str]:
    """
    Extract the subject attributes from a certificate or request as a dictionary. (ro)

    This function iterates through all attributes in the subject of the
    provided object. It maps each attribute name to its string value
    to create a simple key-value collection.

    :param item: The certificate or signing request to be inspected.
    :raises AttributeError: If the provided object does not contain
                            subject information.
    :returns: A dictionary where keys are attribute names and values
              are the corresponding data.
    """
    return {attr.oid._name: str(attr.value) for attr in item.subject}
# !FUNCTION - get_subject_dict

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
