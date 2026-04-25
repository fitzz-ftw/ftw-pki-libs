
Einstieg in den Signer
======================

Dieses Modul bietet den ``CertificateSigner``, um Zertifikatsanfragen (CSR) mit einer 
vorhandenen Root-CA zu signieren.

Signieren eines CSR
-------------------

Wir laden die zuvor erzeugten CA-Dateien und nutzen eine Policy, um die 
Erweiterungen des neuen Zertifikats festzulegen.



>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)

>>> pki_dir = Path("tests_pki_root")
>>> pki_dir.mkdir()
>>> ca_key_path = env.copy2cwd("tests_pki_root/ca.key")
>>> ca_crt_path = env.copy2cwd("tests_pki_root/ca.crt")
>>> csr_path = env.copy2cwd("cert_in/node-01.csr", "node-01.csr")

>>> from ftwpki.baselibs.core import (
...     load_private_key_from_pem, 
...     load_certificate_from_pem,
...     generate_rsa_key_pair,
...     load_csr_from_pem,
... )
>>> from ftwpki.baselibs.signer import CertificateSigner
>>> from ftwpki.baselibs.policies import StandalonePolicy
>>> from ftwpki.baselibs.request import CertificateRequest

Pfade und Passwort definieren

>>> pki_dir = Path("tests_pki_root")
>>> ca_cert_path = pki_dir / "ca.crt"
>>> ca_key_path = pki_dir / "ca.key"
>>> pw = "1234"


CA-Objekte für den Signer laden.
Das Zertifikat laden wir über unsere Core-Utility.

>>> ca_cert = load_certificate_from_pem(ca_cert_path.read_bytes())

Den Key laden wir über unsere Core-Utility

>>> ca_key = load_private_key_from_pem(ca_key_path.read_bytes(), pw)

Signer und eine einfache Policy initialisieren

>>> signer = CertificateSigner(ca_cert=ca_cert, ca_key=ca_key)
>>> policy = StandalonePolicy()

>>> csr = load_csr_from_pem(csr_path.read_bytes())

Den CSR signieren. 

>>> signed_cert = signer.sign(csr=csr, policy=policy, validity_days=365)
>>> pem_data = signer.get_pem(signed_cert)

Überprüfung

>>> b"BEGIN CERTIFICATE" in pem_data
True
>>> str(signer).startswith("CertificateSigner(issuer=")
True


>>> signed_cert = signer.sign(csr=csr, 
...     policy=policy, 
...     validity_days=365,
...     ocspURI="http://my.server.org",
...     )

>>> signed_cert = signer.sign(csr=csr, 
...     policy=policy, 
...     validity_days=365,
...     ocspURI="http:/server.org",
...     )
Warning: 'http:/server.org' is not a valid absolute URL.

>>> signed_cert = signer.sign(csr=csr, 
...     policy=policy, 
...     validity_days=365,
...     ocspURI="https://my.server.org",
...     )
Error: OCSP URI must be HTTP to avoid circular dependencies! Skipping: https://my.server.org

>>> signed_cert = signer.sign(csr=csr, 
...     policy=policy, 
...     validity_days=365,
...     ocspURI="ftp://my.server.org",
...     )
Warning: URI scheme 'ftp' is unusual. Skipping: ftp://my.server.org

>>> signed_cert = signer.sign(csr=csr, 
...     policy=policy, 
...     validity_days=365,
...     ocspURI="http://my.sürver.org",
...     ) #doctest: +NORMALIZE_WHITESPACE
Traceback (most recent call last):
    ...
ValueError: URI values should be passed as an A-label string. 
This means unicode characters should be encoded via a library like idna.


Warning: Could not process AIA URI 'http://my.sürver.org': URI values should be passed 
as an A-label string. This means unicode characters should be encoded via a 
library like idna.

>>> from ftwpki.baselibs.toml_utils import toml2ext_policy

>>> ext_only_toml=env.copy2cwd("toml_2_ext_test_only.toml")

>>> ext_map = toml2ext_policy(filename="toml_2_ext_test_only.toml", section="intermediate") #doctest: +NORMALIZE_WHITESPACE
>>> ext_map #doctest: +NORMALIZE_WHITESPACE
{'ocspURI': 'http://ocsp.deine-pki.test', 
 'crlURI': 'http://pki.deine-pki.test/crl', 
 'caIssuerURI': 'http://pki.deine-pki.test/ca.crt'}

>>> signed_cert = signer.sign(csr=csr, 
...     policy=policy, 
...     validity_days=365,
...     **ext_map
...     ) 

>>> from ftwpki.baselibs.core import save_pem
>>> from ftwpki.baselibs.utils import get_cert_text

>>> save_pem(signer.get_pem(signed_cert), Path("test_cert.pem"))
>>> print(get_cert_text("test_cert.pem")) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Subject:
         CN=node-01.internal,OU=,O=Fitzz TeXnik Welt,L=,ST=,C=DE
    Issuer:
         CN=FTW Dev Root CA,O=FTW Projekte,L=Frankfurt,ST=Hessen,C=DE
    Serial Number:
         ...
    Not Before:
         ...
    Not After:
         ...
    Version:
         v3
    Extensions:
        basicConstraints:
             CA=No, path_length=None
        keyUsage:
             digital_signature, key_encipherment
        extendedKeyUsage:
             serverAuth, clientAuth
        authorityKeyIdentifier:
             b'...'
        authorityInfoAccess:
             OCSP: http://ocsp.deine-pki.test
             caIssuers: http://pki.deine-pki.test/ca.crt
        cRLDistributionPoints:
             http://pki.deine-pki.test/crl
        subjectKeyIdentifier:
             b'w\xf1\x87\xa9\xbe\x80\xf4\xa7\xf1.~\x81\xc3S\xfe\xbc\xd2\xf8\xeb\xa7'

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            ...
        Signature Algorithm: sha512WithRSAEncryption
        Issuer: C=DE, ST=Hessen, L=Frankfurt, O=FTW Projekte, CN=FTW Dev Root CA
        Validity
            Not Before: ...
            Not After : ...
        Subject: C=DE, ST=, L=, O=Fitzz TeXnik Welt, OU=, CN=node-01.internal
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    ...
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Authority Key Identifier: 
                04:C9:E8:B4:30:55:75:5E:E7:BD:66:88:3E:A0:3C:01:65:CF:5A:98
            Authority Information Access: 
                OCSP - URI:http://ocsp.deine-pki.test
                CA Issuers - URI:http://pki.deine-pki.test/ca.crt
            X509v3 CRL Distribution Points: 
                Full Name:
                    URI:http://pki.deine-pki.test/crl
<BLANKLINE>
            X509v3 Subject Key Identifier: 
                77:F1:87:A9:BE:80:F4:A7:F1:2E:7E:81:C3:53:FE:BC:D2:F8:EB:A7
    Signature Algorithm: ...
    Signature Value:
        ...
<BLANKLINE>

>>> ext_map = toml2ext_policy(filename="toml_2_ext_test_only.toml", 
...     section="secureintermediate") #doctest: +NORMALIZE_WHITESPACE
>>> ext_map #doctest: +NORMALIZE_WHITESPACE
{'ocspURI': 'http://ocsp.deine-pki.test', 
 'crlURI': 'http://pki.deine-pki.test/crl_intermediate', 
 'caIssuerURI': 'http://pki.deine-pki.test/ca.crt'}

>>> signed_cert = signer.sign(csr=csr, 
...     policy=policy, 
...     validity_days=365,
...     **ext_map
...     ) 

>>> save_pem(signer.get_pem(signed_cert), Path("test_short.crt.pem"))
>>> print(get_cert_text("test_short.crt.pem")) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Subject:
    ...
    cRLDistributionPoints:
            http://pki.deine-pki.test/crl_intermediate
    ...

Certificate:
    ...
            X509v3 CRL Distribution Points: 
                Full Name:
                    URI:http://pki.deine-pki.test/crl_intermediate
    ...
<BLANKLINE>

>>> from cryptography.hazmat.primitives import serialization
>>> from email.message import EmailMessage
>>> import smime
>>> msg = EmailMessage()
>>> msg.set_content("test")
>>> ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
>>> result = smime.encrypt(msg, ca_cert_pem)
>>> type(result)
<class 'email.mime.text.MIMEText'>

>>> result_bytes = result.as_bytes()
>>> # Prüfen, ob die wichtigsten S/MIME-Marker vorhanden sind
>>> b"MIME-Version: 1.0" in result_bytes
True
>>> b"application/pkcs7-mime" in result_bytes
True
>>> b"base64" in result_bytes
True


>>> env.clean_home()
>>> env.teardown()
