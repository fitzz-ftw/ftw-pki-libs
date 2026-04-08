:orphan:

Einstieg in Root-CA (caroot)
============================

Dieses Modul bietet die ``CertificateAuthority``-Klasse, um eine Root-PKI zu initialisieren. 
Dabei werden ein verschlüsselter privater Schlüssel und ein selbstsigniertes Stammzertifikat erstellt.

.. SECTION - Setup

>>> from fitzzftw.develtool.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)

.. !SECTION



Erstellung der Root-CA
----------------------

Im folgenden Beispiel initialisieren wir eine CA, generieren ein RSA-Schlüsselpaar (4096 Bit) 
und erstellen das Root-Zertifikat. Die Dateien werden anschließend über die ``core``-Utility 
sicher auf die Festplatte geschrieben.

>>> import os
>>> from pathlib import Path
>>> from ftwpki.baselibs.caroot import CertificateAuthority
>>> from ftwpki.baselibs.core import save_pem

Verzeichnis für die PKI-Artefakte vorbereiten

>>> pki_dir = Path("tests_pki_root")
>>> pki_dir.mkdir(parents=True, exist_ok=True)
>>> key_path = pki_dir / "ca.key"
>>> cert_path = pki_dir / "ca.crt"

CA-Instanz mit Metadaten initialisieren

>>> ca = CertificateAuthority(
...     common_name="FTW Dev Root CA",
...     country="DE",
...     state="Hessen",
...     location="Frankfurt",
...     organization="FTW Projekte"
... )

Schlüsselpaar und Zertifikat generieren
Der private Schlüssel wird mit der Passphrase verschlüsselt.

>>> passphrase = "1234"
>>> ca.create_root_certificate(passphrase=passphrase, days=3650)

PEM-Daten dauerhaft speichern.
Wir nutzen 'is_private=True' für den Schlüssel (chmod 600).

>>> save_pem(ca.private_key, key_path, is_private=True)
>>> save_pem(ca.certificate(), cert_path)

Überprüfung

>>> key_path.exists() and cert_path.exists()
True


Verwendung der erzeugten Dateien
--------------------------------

Diese Dateien sind nun vom Quellcode entkoppelt und können von anderen Modulen 
(wie dem Signer) eingelesen werden.

Einlesen des Zertifikats (als Byte-String)

>>> cert_bytes = cert_path.read_bytes()
>>> b"BEGIN CERTIFICATE" in cert_bytes
True


.. SECTION - Teardown

>>> env.teardown()

.. !SECTION
