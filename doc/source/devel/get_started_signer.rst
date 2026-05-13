
Einstieg in den Signer
======================

Dieses Modul bietet den ``CertificateSigner``, um Zertifikatsanfragen (CSR) mit einer 
vorhandenen CA zu signieren.

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
>>> from ftwpki.baselibs.policies import ClientServerPolicy
>>> from ftwpki.baselibs.cert_request import CertificateRequest

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
>>> policy = ClientServerPolicy()

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
        CN=node-01.internal,OU=,O=Fitzz TeXnik Welt,L=,ST=,C=DE
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
            CA=No, path_length=None
    keyUsage:
            digital_signature, key_encipherment
    extendedKeyUsage:
            serverAuth, clientAuth
    authorityKeyIdentifier:
            b'\x04\xc9\xe8\xb40Uu^\xe7\xbdf\x88>\xa0<\x01e\xcfZ\x98'
    authorityInfoAccess:
            OCSP: http://ocsp.deine-pki.test
            caIssuers: http://pki.deine-pki.test/ca.crt
    cRLDistributionPoints:
            http://pki.deine-pki.test/crl_intermediate
    subjectKeyIdentifier:
            b'w\xf1\x87\xa9\xbe\x80\xf4\xa7\xf1.~\x81\xc3S\xfe\xbc\xd2\xf8\xeb\xa7'



>>> env.clean_home()
>>> env.teardown()
