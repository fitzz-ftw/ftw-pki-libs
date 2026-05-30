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

>>> from ftwpki.baselibs.utils import get_cert_text_from_cert
>>> print(get_cert_text_from_cert(ca_cert)) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Subject:
        CN=FTW Dev Root CA,O=FTW Projekte,L=Frankfurt,ST=Hessen,C=DE
Issuer:
        CN=FTW Dev Root CA,O=FTW Projekte,L=Frankfurt,ST=Hessen,C=DE
Serial Number:
        ...
Not Before:
        20...
Not After:
        20...
Version:
        v3
Extensions:
    basicConstraints:
            CA=Yes, path_length=None
    keyUsage:
            key_cert_sign, crl_sign
    subjectKeyIdentifier:
            b'...'

>>> class StubExt2:
...     value = val
...     class oid:
...         _name = "exoticOID"


>>> print(format_extension(StubExt2()))
exoticOID:
 key_agreement, encipher_only

>>> from ftwpki.baselibs.utils import report_error, print_error

>>> report_error(Exception("You do not see me here, only in terminal."))

>>> print_error(Exception("I will be seen although here."))
I will be seen although here.

>>> env.clean_home()
>>> env.teardown()
