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
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509 import Certificate

from ftwpki.baselibs.utils import assert_is_pem_cert  #get_cert_text_from_cert


# FUNCTION - Transport Identity
def _get_transport_identity() -> x509.Name:
    """
    Return the standardized identity for PKCS7 transport envelopes. (ro)

    This internal helper creates a specific X.509 Name object used to
    identify the transport service during the creation of PKCS7
    containers.

    :returns: An x509.Name object with the 'FTW-PKI-Transport-Service'
              common name.
    """
    return x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "FTW-PKI-Transport-Service")])

# !FUNCTION - Transport Identity
#FUNCTION - Transport Serialnumber
def _transportserialnumber()->int:
    """
    Return a static serial number for transport dummy certificates. (ro)

    This internal helper generates a large, fixed integer used as a
    serial number for temporary certificates within transport envelopes.
    The number is derived from a repeating numeric pattern.

    :returns: A static integer value used for transport certificate
              identification.
    """
    return int("42" * 23)
# !FUNCTION - Transport Serialnumber


# FUNCTION - Validate and Format Chain
def validate_and_format_chain(*chain_parts: bytes) -> bytes:
    """
    Validate multiple certificate parts and join them into a single chain. (ro)

    This function processes several byte-encoded certificate parts. It
    ensures each part is a valid PEM certificate, removes extra
    whitespace, and combines them into a single formatted block.

    :param chain_parts: Variable number of certificate parts as bytes.
    :raises AssertionError: If any part is not a valid PEM certificate.
    :returns: A single bytes object containing the formatted certificate chain.
    """
    validated: list[bytes] = []
    for i, part in enumerate(chain_parts, 1):
        assert_is_pem_cert(part.strip(), f"Chainpart {i}")
        validated.append(part.strip())
    return b"\n".join(validated)


# !FUNCTION - Validate and Format Chain


# FUNCTION - Create Emphemeral Certifikat
def create_ephemeral_cert(
    public_key: RSAPublicKey,
    signing_key: RSAPrivateKey,
) -> Certificate:
    """
    Create a temporary X.509 certificate for PKCS7 operations. (rw)

    This function generates a short-lived certificate used as a technical
    container for RSA keys. It is required by the PKCS7 API to identify
    recipients through issuer and serial information. Depending on the
    use case, the certificate is either self-signed or signed by a CA.

    :param public_key: The RSA public key to be included in the certificate.
    :param signing_key: The RSA private key used to sign the certificate.
    :returns: A temporary X.509 certificate object valid for a short period.
    """
    subject = _get_transport_identity()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(public_key)
        .serial_number(_transportserialnumber())
        .not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
        )
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
            )
        .sign(signing_key, hashes.SHA256())
    )
    return cert


# !FUNCTION - Create Emphemeral Certifikat
# FUNCTION - Encrypt Transport Package
def encrypt_transport_package(
    user_cert: x509.Certificate,
    root_ca_cert: x509.Certificate,
    private_key: RSAPrivateKey,
    recipient_cert: x509.Certificate,
    *intermediate_certs: x509.Certificate,
    **kwargs,
) -> bytes:
    """
    Create an S/MIME encrypted ZIP package containing certificate data. (rw)

    This function bundles identity certificates, the root CA, and any
    intermediates into a compressed ZIP archive. The archive is then
    encrypted for a specific recipient using PKCS7/SMIME. It allows
    adding optional message files or custom data via keyword arguments.

    :param user_cert: The primary identity certificate to include.
    :param root_ca_cert: The root CA certificate for the trust anchor.
    :param private_key: The RSA private key used for the encryption process.
    :param recipient_cert: The certificate used to encrypt the final package.
    :param intermediate_certs: Variable number of intermediate certificates.
    :param kwargs: Optional settings:
                   - name_user (str): Filename for the user certificate.
                   - name_chain (str): Filename for the certificate chain.
                   - name_ca (str): Filename for the root CA file.
                   - additional_files (dict): Map of {filename: bytes}.
                   - message (str/bytes): Optional text file content.
    :raises TypeError: If provided certificate objects are invalid.
    :returns: The encrypted PEM-encoded data as bytes.
    """
    name_user = kwargs.get("name_user", "user.crt")
    name_chain = kwargs.get("name_chain", "certificate_chain.pem")
    name_ca = kwargs.get("name_ca", "ca.crt")

    user_pem = user_cert.public_bytes(Encoding.PEM)
    root_pem = root_ca_cert.public_bytes(Encoding.PEM)

    intermediate_pems = [c.public_bytes(Encoding.PEM) for c in intermediate_certs]

    full_chain = validate_and_format_chain(*intermediate_pems, root_pem)

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(name_user, user_pem)
        zf.writestr(name_chain, full_chain)
        zf.writestr(name_ca, root_pem)

        if "message" in kwargs:
            zf.writestr("message.txt", kwargs["message"])

        extra_files = kwargs.get("additional_files", {})
        for fname, content in extra_files.items():
            zf.writestr(fname, content)

    zip_bytes = zip_buffer.getvalue()

    return encrypt_bytedata(zip_bytes, recipient_cert, private_key)


# !FUNCTION - Encrypt Transport Package


# FUNCTION - Decrypt Transport Package
def decrypt_transport_package(encrypted_data: bytes, private_key: RSAPrivateKey) -> bytes:
    """
    Decrypt a PKCS7 enveloped transport package. (rw)

    This function reverses the encryption of a transport package. It
    internally generates a temporary ephemeral certificate from the
    provided private key to satisfy the PKCS7 API requirements for
    recipient identification.

    :param encrypted_data: The encrypted PEM-encoded data of the package.
    :param private_key: The RSA private key belonging to the recipient.
    :raises ValueError: If the decryption fails, the data is malformed,
                        or the key does not match the envelope.
    :returns: The decrypted binary data, typically a ZIP archive.
    """
    recipient_cert = create_ephemeral_cert(public_key=private_key.public_key(),
                                           signing_key=private_key, 
                                           )
    options = []

    return pkcs7.pkcs7_decrypt_smime(encrypted_data, recipient_cert, private_key, options)


# !FUNCTION - Decrypt Transport Package
# FUNCTION - Encrypt Bytedata
def encrypt_bytedata(
    unencrypted_data: bytes, recipient_cert: x509.Certificate, ca_key: RSAPrivateKey
):
    """
    Encrypt binary data into a PKCS7 envelope (S/MIME). (rw)

    This function wraps raw binary data in a secure PKCS7 container,
    making it compatible with 'openssl smime' commands. It uses an
    ephemeral transport certificate to identify the recipient within
    the envelope. The data is encrypted using AES-256-CBC by default.

    :param unencrypted_data: The raw binary data to be encrypted.
    :param recipient_cert: The X.509 certificate of the intended recipient.
    :param ca_key: The private key used to sign the ephemeral transport
                   certificate.
    :returns: The encrypted data in S/MIME format (PEM with headers).
    """
    options = [pkcs7.PKCS7Options.Binary]


    transport_dummy = create_ephemeral_cert(
        public_key=recipient_cert.public_key(),
        signing_key=ca_key,   # Hier muss ein Key her
    )

    builder = pkcs7.PKCS7EnvelopeBuilder().set_data(unencrypted_data)
    builder = builder.add_recipient(transport_dummy)  # <-- HIER wird jetzt der Dummy genutzt!
    builder = builder.add_recipient(recipient_cert)

    return builder.encrypt(Encoding.SMIME, options)

# !FUNCTION - Encrypt Bytedata


# FUNCTION - Decrypt Bytedata
def decrypt_bytedata(
    encrypted_data: bytes, recipient_key: RSAPrivateKey, recipient_cert: x509.Certificate
) -> bytes:
    """
    Decrypt an S/MIME package to recover raw binary content. (rw)

    This function processes PKCS7 enveloped data using the recipient's
    private key and certificate. It is specifically designed to extract
    the original binary payload (such as a ZIP archive) from an S/MIME
    transport container.

    :param encrypted_data: The S/MIME encrypted PEM-encoded data.
    :param recipient_key: The RSA private key used for decryption.
    :param recipient_cert: The X.509 certificate belonging to the key.
    :raises ValueError: If decryption fails due to malformed data,
                        unsupported algorithms, or a key mismatch.
    :returns: The decrypted raw bytes of the original content.
    """
    options = []

    try:
        decrypted_data = pkcs7.pkcs7_decrypt_smime(
            encrypted_data, recipient_cert, recipient_key, options
        )
        return decrypted_data
    except Exception as e:
        raise ValueError(f"Entschlüsselung fehlgeschlagen: {e}")

# !FUNCTION - Decrypt Bytedata


if __name__ == "__main__":  # pragma: no cover
    # import cryptography
    # from cryptography.hazmat.primitives.serialization import pkcs7
    # print(f"PATH: {cryptography.__file__}")
    # print(f"VERSION: {cryptography.__version__}")
    # print(f"OPTIONS: {dir(pkcs7.PKCS7Options)}")
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
