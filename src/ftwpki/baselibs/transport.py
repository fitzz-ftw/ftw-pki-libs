# File: src/ftwpki/baselibs/transport.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
Transport module for secure package handling.
==============================================

This module provides functionality to bundle certificates and keys into
encrypted ZIP archives using PKCS7 (S/MIME). It ensures that sensitive
data can be safely transmitted between the signer and the receiver.

The module handles:
* Creating encrypted transport packages (ZIP in PKCS7).
* Decrypting transport packages using ephemeral certificates.
* Identification of recipients via RSA public keys.
"""

import datetime
import io
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID

from ftwpki.baselibs.utils import assert_is_pem_cert


# FUNCTION - Validate and Format Chain
def validate_and_format_chain(*chain_parts: bytes) -> bytes:
    """
    Validates multiple certificate parts and joins them into a single chain.

    Each part is checked to ensure it is a valid PEM-encoded certificate.
    Trailing and leading whitespaces are removed from each part before
    joining them with a newline character.

    :param chain_parts: Variable number of certificate parts as bytes.
    :return: A single bytes object containing the formatted certificate chain.
    :raises AssertionError: If a part is not a valid PEM certificate.
    """
    validated: list[bytes] = []
    for i, part in enumerate(chain_parts, 1):
        assert_is_pem_cert(part.strip(), f"Chainpart {i}")
        validated.append(part.strip())
    return b"\n".join(validated)


# !FUNCTION - Validate and Format Chain


# FUNCTION - Create Emphemeral Certifikat
def create_ephemeral_cert(private_key: RSAPrivateKey) -> Certificate:
    """
    Creates a temporary self-signed certificate to satisfy the PKCS7 API.

    This is a technical workaround because the cryptography PKCS7 API
    requires a certificate object to identify the recipient, even though
    RSA decryption mathematically only requires the private key.

    :param private_key: The RSA private key of the recipient.
    :return: A temporary X.509 certificate object containing the public key.
    """
    # Ein minimales Zertifikat bauen, das nur als Key-Träger dient
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ephemeral Receiver")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )

    return cert


# !FUNCTION - Create Emphemeral Certifikat
# FUNCTION - Encrypt Taransport Package
# old name: create_encrypted_zipfile
def encrypt_transport_package(
    user_cert: x509.Certificate,
    root_ca_cert: x509.Certificate,
    recipient_cert: x509.Certificate,
    *intermediate_certs: x509.Certificate,
    **kwargs,
) -> bytes:
    """
    Creates an S/MIME encrypted ZIP package containing certificates and optional files.

    The function bundles the user certificate, the root CA, and any intermediates into
    a ZIP archive, which is then encrypted for the specified recipient.

    :param user_cert: The main certificate to be included.
    :param root_ca_cert: The root CA certificate.
    :param recipient_cert: The certificate used to encrypt the final package.
    :param intermediate_certs: Variable number of intermediate CA certificates.
    :param kwargs: Optional settings for the package content:
        - name_user (str): Filename for the user certificate (default: 'user.crt').
        - name_chain (str): Filename for the certificate chain (default: 'certificate_chain.pem').
        - name_ca (str): Filename for the root CA certificate (default: 'ca.crt').
        - additional_files (dict): Dictionary of {filename: bytes} to include.
        - message (str/bytes): An optional message file 'message.txt'.
    :return: The S/MIME encrypted PEM data as bytes.
    :raises TypeError: If any provided certificate is not a valid x509.Certificate.
    """
    name_user = kwargs.get("name_user", "user.crt")
    name_chain = kwargs.get("name_chain", "certificate_chain.pem")
    name_ca = kwargs.get("name_ca", "ca.crt")

    # 1. Zertifikate in PEM umwandeln (knallt hier bei falschem Typ -> gut so!)
    user_pem = user_cert.public_bytes(Encoding.PEM)
    root_pem = root_ca_cert.public_bytes(Encoding.PEM)

    # Intermediates umwandeln
    intermediate_pems = [c.public_bytes(Encoding.PEM) for c in intermediate_certs]

    # 2. Die Kette formatieren (nur Intermediates + Root)
    # Wenn dein Bash-Skript die komplette Kette in einer Datei will:
    full_chain = validate_and_format_chain(*intermediate_pems, root_pem)

    # 3. ZIP im RAM erstellen
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Das eigentliche Zertifikat
        zf.writestr(name_user, user_pem)
        # Die Kette für den Pfad (Intermediates + Root)
        zf.writestr(name_chain, full_chain)
        # Das nackte Root-Zertifikat für den Trust-Store
        zf.writestr(name_ca, root_pem)

        # Beispiel für zukünftige Flexibilität durch **kwargs:
        # Eine Nachricht/Kommentar hinzufügen
        if "message" in kwargs:
            zf.writestr("message.txt", kwargs["message"])

        # Beliebige weitere Dateien aus einem Dict hinzufügen
        extra_files = kwargs.get("additional_files", {})
        for fname, content in extra_files.items():
            zf.writestr(fname, content)

    zip_bytes = zip_buffer.getvalue()

    # 4. Ab in die ausgelagerte Verschlüsselung
    return encrypt_bytedata(zip_bytes, recipient_cert)


# !FUNCTION - Encrypt Taransport Package


# FUNCTION - Decrypt Transport Package
def decrypt_transport_package(encrypted_data: bytes, private_key: RSAPrivateKey) -> bytes:
    """
    Decrypts a PKCS7 enveloped transport package.

    :param encrypted_data: The encrypted PEM data of the transport package.
    :param private_key: The RSA private key of the recipient.
    :return: The decrypted binary data (usually a ZIP file).
    :raises ValueError: If the decryption fails or the key does not match.
    """
    #
    # 1. Erstelle das Dummy-Zertifikat aus dem Key
    recipient_cert = create_ephemeral_cert(private_key)

    # 2. Nutze die strikte cryptography-API mit unserem Hilfsobjekt
    return pkcs7.pkcs7_decrypt_pem(encrypted_data, recipient_cert, private_key, [])


# !FUNCTION - Decrypt Transport Package
# FUNCTION - Encrypt Bytedata
def encrypt_bytedata(unencrypted_data, recipient_cert):
    """
    Encrypts binary data into a PKCS7 envelope (S/MIME).

    The output is compatible with the 'openssl smime -decrypt -binary' command.
    The encryption uses AES-256-CBC by default as per the cryptography
    library's PKCS7 implementation.

    :param unencrypted_data: The raw binary data to be encrypted (e.g., a ZIP file).
    :param recipient_cert: The X.509 certificate of the intended recipient.
    :return: The encrypted data in S/MIME format (PEM with headers).
    """
    options = [pkcs7.PKCS7Options.Binary]  # Wichtig für ZIP-Dateien!

    builder = pkcs7.PKCS7EnvelopeBuilder().set_data(unencrypted_data)
    builder = builder.add_recipient(recipient_cert)

    # Wir nutzen SMIME-Encoding, damit die Header für OpenSSL da sind
    return builder.encrypt(Encoding.SMIME, options)


# !FUNCTION - Encrypt Bytedata


# FUNCTION - Decrypt Bytedata
def decrypt_bytedata(
    encrypted_data: bytes, recipient_key: RSAPrivateKey, recipient_cert: x509.Certificate
) -> bytes:
    """
    Decrypts an S/MIME package and returns the raw binary content.

    This function uses the native cryptography (v44+) implementation to
    process PKCS7 enveloped data. It is designed to recover the original
    ZIP archive from the transport package.

    :param encrypted_data: The S/MIME encrypted PEM data.
    :param recipient_key: The RSA private key for decryption.
    :param recipient_cert: The X.509 certificate of the recipient.
    :return: The decrypted raw bytes (usually a ZIP file).
    :raises ValueError: If decryption fails due to invalid data or key mismatch.
    """
    # 1. Zertifikat und Key laden (Gatekeeper-Style)
    # cert = x509.load_pem_x509_certificate(recipient_cert)
    # key = recipient_key #serialization.load_pem_private_key(recipient_key_pem, password=None)

    # 2. Entschlüsseln
    # Leere options [] erlauben Binary-Daten (unser ZIP)
    options = []

    try:
        decrypted_data = pkcs7.pkcs7_decrypt_smime(
            encrypted_data, recipient_cert, recipient_key, options
        )
        return decrypted_data
    except Exception as e:
        raise ValueError(f"Entschlüsselung fehlgeschlagen: {e}")


# FUNCTION - Decrypt Bytedata


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
    test_file = testfiles_dir / "get_started_transport.rst"

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
