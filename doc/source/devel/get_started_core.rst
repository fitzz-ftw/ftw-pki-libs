
Get Started: PKI Core Utilities
===============================

Dieses Modul stellt die grundlegenden kryptografischen Werkzeuge bereit. 
Alle Beispiele laufen in einer isolierten Testumgebung.


2. RSA-Schlüssel (generate_rsa_key_pair & load_private_key_from_pem)
--------------------------------------------------------------------

Wir erzeugen ein Schlüsselpaar und laden es zur Verifizierung wieder ein.

>>> from ftwpki.baselibs.core import generate_rsa_key_pair
>>> passw = "CoreSecret2026"
>>> priv_pem, pub_pem = generate_rsa_key_pair(passw, key_size=2048)
>>> b"BEGIN ENCRYPTED PRIVATE KEY" in priv_pem
True

>>> b"BEGIN PUBLIC KEY" in pub_pem
True


3. Identitäten (create_distinguished_name)
------------------------------------------

Erstellung von X.509 Namen mit Pflichtfeldern und optionalen Attributen.

>>> from ftwpki.baselibs.core import create_distinguished_name

Vollständiger Name

>>> dn_full = create_distinguished_name(
...     "My Node", "DE", "NRW", "RS", "Fritz", "Dev-Unit", "fritz@example.org"
... )
>>> str(dn_full)
'<Name(C=DE,ST=NRW,L=RS,O=Fritz,OU=Dev-Unit,1.2.840.113549.1.9.1=fritz@example.org,CN=My Node)>'

Minimaler Name (Punkte unterdrücken optionale Felder)

>>> dn_min = create_distinguished_name("Small Node", "DE", "NRW", "RS", "Fritz", ".", ".")
>>> str(dn_min)
'<Name(C=DE,ST=NRW,L=RS,O=Fritz,CN=Small Node)>'


5. Transformationen (get_pem_bytes & create_chain_bytes)
-----------------------------------------------------------

Handling von Zertifikatsobjekten und Ketten.

>>> from ftwpki.baselibs.core import get_pem_bytes, create_chain_bytes

Stub-Objekt für X.509 Schnittstelle

>>> class StubX509:
...     def public_bytes(self, encoding): return b"CERT_DATA"

>>> cert = StubX509()
>>> get_pem_bytes(cert)
b'CERT_DATA'

>>> create_chain_bytes([cert, cert])
b'CERT_DATACERT_DATA'


6. Fehlerbehandlung
-------------------

Fehlgeschlagene Entschlüsselung wirft einen sauberen ValueError.

>>> from ftwpki.baselibs.core import load_private_key_from_pem
>>> load_private_key_from_pem(priv_pem, "falsches_passwort")
Traceback (most recent call last):
    ...
ftwpki.baselibs.exceptions.PKIEncryptionError: Could not decrypt or load the private key. Check your passphrase.


>>> private_key_obj= load_private_key_from_pem(priv_pem, passw)

>>> from pathlib import Path
>>> from fitzzftw.develtool.testinfra import TestHomeEnvironment
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)

4. Sicher Speichern (save_pem)
------------------------------

Wir prüfen die automatische Ordnererstellung und die Dateiberechtigungen.

>>> from ftwpki.baselibs.core import save_pem
>>> cert_dir = Path("archive/2026")
>>> key_file = cert_dir / "root.key"

is_private=True sorgt für chmod 600 auf Linux/Unix

>>> save_pem(priv_pem, key_file, is_private=True)
>>> key_file.exists()
True

>>> key_stat= key_file.stat().st_mode

>>> import stat

>>> stat.filemode(key_stat)
'-rw-------'


>>> key_file.unlink()
>>> save_pem(priv_pem, key_file, is_private=False)
>>> key_file.exists()
True

>>> key_stat= key_file.stat().st_mode

>>> stat.filemode(key_stat)
'-rw-r--r--'



>>> csr_path = env.copy2cwd("cert_in/node-01.csr", "node-01.csr")
>>> cert_path = env.copy2cwd("tests_pki_root/ca.crt", "ca.crt")

Zertifikat laden

>>> from ftwpki.baselibs.core import load_certificate_from_pem

>>> cert_obj = load_certificate_from_pem(cert_path.read_bytes())
>>> cert_obj.subject
<Name(C=DE,ST=Hessen,L=Frankfurt,O=FTW Projekte,CN=FTW Dev Root CA)>


Certificate Signing Request (CSR) laden

>>> from ftwpki.baselibs.core import load_csr_from_pem

>>> csr_obj = load_csr_from_pem(csr_path.read_bytes())
>>> csr_obj.subject
<Name(C=DE,ST=,L=,O=Fitzz TeXnik Welt,OU=,CN=node-01.internal)>



>>> from ftwpki.baselibs.core import create_csr_name
>>> stl = ["dies ist", "ein Test"]
>>> create_csr_name(*stl)
'dies-ist_ein-Test.csr'

>>> from ftwpki.baselibs.core import cert_to_record

>>> cert_record = cert_to_record(cert_obj)
>>> cert_record # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
CertificateRecord(status='V', 
    expiry=datetime.datetime(...), 
    revocation_date='', 
    serial='...', 
    subject='CN=FTW Dev Root CA,O=FTW Projekte,L=Frankfurt,ST=Hessen,C=DE', 
    filename='unknown')

>>> from ftwpki.baselibs.core import revoke_record

>>> rev_record = revoke_record(cert_record, "corrupted")
>>> rev_record2 = revoke_record(cert_record)
>>> rev_record3 = revoke_record(cert_record, "keyCompromise")
>>> rev_record # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
CertificateRecord(status='R', 
    expiry=datetime.datetime(2036, 4, 4, 14, 20, 39, tzinfo=datetime.timezone.utc), 
    revocation_date='...,corrupted', 
    serial='5CE58D3B36B3C88D9F15772D10CC51A54203FEF0', 
    subject='CN=FTW Dev Root CA,O=FTW Projekte,L=Frankfurt,ST=Hessen,C=DE', 
    filename='unknown')


>>> from ftwpki.baselibs.core import create_crl

>>> crl=create_crl(revoked_records=[rev_record, rev_record2, rev_record3, cert_record],
...     ca_cert=cert_obj,
...     ca_key=private_key_obj)

>>> crl # doctest: +ELLIPSIS
<cryptography.hazmat.bindings._rust.x509.CertificateRevocationList object at ...>

>>> env.teardown()
