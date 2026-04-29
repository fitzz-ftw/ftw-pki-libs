Using the Transport Module
==========================

The transport module handles the secure packaging of certificates. It bundles 
files into a ZIP archive and encrypts it using PKCS7 (S/MIME).

Setup Environment
------------------

.. SECTION - Setup Environment

>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)

.. !SECTION - Setup Environment

Preparation
-----------

>>> Path("tests_pki_root").mkdir()
>>> ca_key_path = env.copy2cwd("tests_pki_root/ca.key")
>>> ca_cert_path = env.copy2cwd("tests_pki_root/ca.crt")
>>> csr_path = env.copy2cwd("cert_in/node-01.csr", "node-01.csr")
>>> pw = "1234"

>>> from ftwpki.baselibs.core import (
...     load_private_key_from_pem, 
...     load_certificate_from_pem,
...     generate_rsa_key_pair,
...     load_csr_from_pem,
... )


Root-CA als CertObjekt
>>> ca_cert = load_certificate_from_pem(ca_cert_path.read_bytes())

Root-CA Privatkey
>>> ca_key = load_private_key_from_pem(ca_key_path.read_bytes(), pw)

>>> from cryptography.hazmat.primitives import serialization

Root-CA als bytes
>>> ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)




>>> from ftwpki.baselibs.transport import validate_and_format_chain

Wir nehmen das CA-Cert einfach zweimal als Kette

>>> chain = validate_and_format_chain(ca_cert_pem, ca_cert_pem)
>>> len(chain.strip()) >= len(ca_cert_pem.strip())*2
True

>>> b"-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----" in chain
True

>>> chain = validate_and_format_chain(ca_cert_pem, ca_cert_pem, ca_cert_pem)

Jetz chain als dreier certificat.
>>> len(chain.strip()) >= len(ca_cert_pem.strip())*3
True

>>> chain4 = validate_and_format_chain(ca_cert_pem, chain)
>>> len(chain4.strip()) >= len(ca_cert_pem.strip())*4
True

Test 1: Ein faules Ei in der Mitte der Kette

>>> validate_and_format_chain(ca_cert_pem, b"MUELL", ca_cert_pem) #doctest: +ELLIPSIS
Traceback (most recent call last):
    ...
ValueError: 'Chainpart 2' ist kein gültiges PEM-Zertifikat: ...

Test 2: Falscher Typ in der Kette

>>> validate_and_format_chain(ca_cert_pem, str(123))
Traceback (most recent call last):
    ...
TypeError: 'Chainpart 2' muss vom Typ 'bytes' sein, nicht str.


>>> from ftwpki.baselibs.transport import encrypt_transport_package

Wir erstellen das Paket
signed_pem und user_cert_pem sind hier zum Testen identisch mit 
der CA

>>> p7m_bytes = encrypt_transport_package(
...     ca_cert, 
...     ca_cert,
...     ca_key, 
...     ca_cert
... ) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE


Prüfen, ob wir Daten zurückbekommen haben

>>> isinstance(p7m_bytes, bytes)
True

>>> len(p7m_bytes) > 1000  # Ein S/MIME Paket hat eine gewisse Mindestgröße
True

Technischer Check: Enthält das Ergebnis die S/MIME Header?

>>> b"Content-Type: application/pkcs7-mime" in p7m_bytes
True
>>> b"smime.p7m" in p7m_bytes
True

Optional: Prüfen, ob der Content-Transfer-Encoding Header 
vorhanden ist

>>> b"base64" in p7m_bytes.lower()
True


>>> from ftwpki.baselibs.transport import decrypt_bytedata
>>> import io
>>> import zipfile


1. Entschlüsseln
p7m_bytes ist das Ergebnis von create_encrypted_zipfile aus dem 
vorherigen Test

>>> decrypted_zip_bytes = decrypt_bytedata(
...     p7m_bytes,
...     ca_key,
...     ca_cert
... )

1. Validierung: Sind es ZIP-Bytes?

>>> decrypted_zip_bytes.startswith(b"PK\x03\x04")
True

1. Inhalt prüfen: Ist unsere Kette drin?

>>> with zipfile.ZipFile(io.BytesIO(decrypted_zip_bytes)) as zf:
...     "certificate_chain.pem" in zf.namelist()
True

1. Kette extrahieren und Typ-Check

>>> with zipfile.ZipFile(io.BytesIO(decrypted_zip_bytes)) as zf:
...     extracted_chain = zf.read("certificate_chain.pem")
>>> b"-----BEGIN CERTIFICATE-----" in extracted_chain
True

>>> with zipfile.ZipFile(io.BytesIO(decrypted_zip_bytes)) as zf:
...     zf.namelist()
['user.crt', 'certificate_chain.pem', 'ca.crt']

>>> p7m_bytes_with_info = encrypt_transport_package(
...     ca_cert, 
...     ca_cert, 
...     ca_key, 
...     ca_cert,
...     message = "test message",
...     additional_files = {"readme.txt": "Readme\nfor\nPackage ..."}
... ) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE


>>> decrypted_zip_bytes_with_info = decrypt_bytedata(
...     p7m_bytes_with_info,
...     ca_key,
...     ca_cert
... )


>>> with zipfile.ZipFile(io.BytesIO(decrypted_zip_bytes_with_info)) as zf:
...     zf.namelist()
['user.crt', 'certificate_chain.pem', 'ca.crt', 'message.txt', 'readme.txt']

>>> decrypted_zip_bytes_with_info = decrypt_bytedata(
...     p7m_bytes_with_info[:-10],
...     ca_key,
...     ca_cert
... ) #doctest: +NORMALIZE_WHITESPACE +ELLIPSIS
Traceback (most recent call last):
    ...
ValueError: Entschlüsselung fehlgeschlagen: 
    error parsing asn1 value: ParseError { kind: ShortData { needed: 5 } }

Testing the Ephemeral Workaround
--------------------------------

Directly testing the internal certificate creation for the decryption workaround:

>>> from ftwpki.baselibs.transport import create_ephemeral_cert

>>> from cryptography import x509
>>> from cryptography.x509.oid import NameOID

>>> ephemeral_cert = create_ephemeral_cert(ca_key.public_key(), ca_key) #doctest:+ELLIPSIS +NORMALIZE_WHITESPACE

>>> isinstance(ephemeral_cert, x509.Certificate)
True

>>> ephemeral_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
'FTW-PKI-Transport-Service'

2. Testing the high-level decryption wrapper:
(This ensures coverage for the lines 170-173)

>>> from ftwpki.baselibs.transport import decrypt_transport_package

>>> transfer_file_path = Path("testtransport").with_suffix(".zip.enc")
>>> _ = transfer_file_path.write_bytes(p7m_bytes)

>>> transfer_file = transfer_file_path.as_posix()

>>> transfer_file
'testtransport.zip.enc'

>> p7m_bytes

>>> from ftwpki.baselibs.openssl_comp import openssl_decrypt_smime_file

>>> openssl_decrypt_smime_file(input_file = transfer_file, 
...     key_file = ca_key_path.as_posix(), password=pw)
True

>>> print(type(ca_key))
<class 'cryptography.hazmat.bindings._rust.openssl.rsa.RSAPrivateKey'>

>>> print(dir(ca_key)) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE 
['..., 'decrypt', 'key_size', 'private_bytes', 'private_numbers', 'public_key', 'sign']

>> ca_key.public_key()

>>> # package_data wurde weiter oben im File bereits erstellt
>>> decrypted = decrypt_transport_package(p7m_bytes, ca_key) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
>>> decrypted.startswith(b"PK")
True


..SECTION - Teardown Environment

>>> env.clean_home()
>>> env.teardown()

..!SECTION - Teardown Environment
