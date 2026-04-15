
Einstieg in den Signer
======================

Dieses Modul bietet den ``CertificateSigner``, um Zertifikatsanfragen (CSR) mit einer 
vorhandenen Root-CA zu signieren.

Signieren eines CSR
-------------------

Wir laden die zuvor erzeugten CA-Dateien und nutzen eine Policy, um die 
Erweiterungen des neuen Zertifikats festzulegen.



>>> from fitzzftw.develtool.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)

>>> Path("tests_pki_root").mkdir()
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

>>> env.teardown()

>>> signed_cert = signer.sign(csr=csr, 
...     policy=policy, 
...     validity_days=365,
...     authorityInfoAccess="http://my.server.org",
...     )

>>> signed_cert = signer.sign(csr=csr, 
...     policy=policy, 
...     validity_days=365,
...     authorityInfoAccess="http:/server.org",
...     )
Warning: 'http:/server.org' is not a valid absolute URL.

>>> signed_cert = signer.sign(csr=csr, 
...     policy=policy, 
...     validity_days=365,
...     authorityInfoAccess="https://my.server.org",
...     )
Error: OCSP URI must be HTTP to avoid circular dependencies! Skipping: https://my.server.org

>>> signed_cert = signer.sign(csr=csr, 
...     policy=policy, 
...     validity_days=365,
...     authorityInfoAccess="ftp://my.server.org",
...     )
Warning: URI scheme 'ftp' is unusual for OCSP. Skipping.

>>> signed_cert = signer.sign(csr=csr, 
...     policy=policy, 
...     validity_days=365,
...     authorityInfoAccess="http://my.sürver.org",
...     ) #doctest: +NORMALIZE_WHITESPACE
Warning: Could not process AIA URI 'http://my.sürver.org': URI values should be passed 
as an A-label string. This means unicode characters should be encoded via a 
library like idna.
