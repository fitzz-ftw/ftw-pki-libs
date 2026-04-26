Utilities
=========

>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)

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

>>> from ftwpki.baselibs.utils import assert_is_pem_cert

>>> assert_is_pem_cert(ca_cert_pem, "Root-CA")

>>> assert_is_pem_cert(str(ca_cert_pem), "Root-CA")
Traceback (most recent call last):
    ...
TypeError: 'Root-CA' muss vom Typ 'bytes' sein, nicht str.

>>> assert_is_pem_cert(ca_cert_pem[3:], "Root-CA") #doctest: +NORMALIZE_WHITESPACE
Traceback (most recent call last):
    ...
ValueError: 'Root-CA' ist kein gültiges PEM-Zertifikat: 
Unable to load PEM file. 
See https://cryptography.io/en/latest/faq/#why-can-t-i-import-my-pem-file 
for more details. MalformedFraming


>>> from ftwpki.baselibs.utils import validate_and_format_chain

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

>>> from ftwpki.baselibs.utils import create_encrypted_zipfile

Wir erstellen das Paket
signed_pem und user_cert_pem sind hier zum Testen identisch mit 
der CA

>>> p7m_bytes = create_encrypted_zipfile(
...     ca_cert, 
...     ca_cert, 
...     ca_cert
... )

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


>>> from ftwpki.baselibs.utils import decrypt_bytedata
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


>>> from ftwpki.baselibs.utils import format_extension

>>> class StubExt:
...     value = "Unbekannter Wert"
...     class oid:
...         _name = "exoticOID"
>>> format_extension(StubExt())
'exoticOID: Unbekannter Wert'

>>> from cryptography.x509 import KeyUsage
>>> val = KeyUsage(
...     digital_signature=False, content_commitment=False,
...     key_encipherment=False, data_encipherment=False,
...     key_agreement=True, # Das triggert den Zweig
...     key_cert_sign=False, crl_sign=False,
...     encipher_only=True, decipher_only=False
... )

>>> class StubExt2:
...     value = val
...     class oid:
...         _name = "exoticOID"


>>> print(format_extension(StubExt2()))
exoticOID:
 key_agreement, encipher_only

>>> p7m_bytes_with_info = create_encrypted_zipfile(
...     ca_cert, 
...     ca_cert, 
...     ca_cert,
...     message = "test message",
...     additional_files = {"readme.txt": "Readme\nfor\nPackage ..."}
... )

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

>>> env.clean_home()
>>> env.teardown()
