Get Started: Certificate Request
================================

Dieses Modul stellt den ``CertificateRequest`` bereit, um Certificate Signing 
Requests (CSR) auf Basis von Policies zu erstellen.

1. Erstellung eines Requests (Automatisierter Workflow)
-------------------------------------------------------

In automatisierten Umgebungen werden Schlüssel oft ohne Passphrase erzeugt 
oder geladen, um eine nahtlose Verarbeitung durch Dienste zu ermöglichen.

>>> from ftwpki.baselibs.core import (
...     generate_rsa_key_pair, 
...     load_private_key_from_pem, 
...     create_distinguished_name
... )
>>> from ftwpki.baselibs.policies import ClientServerPolicy
>>> from ftwpki.baselibs.request import CertificateRequest

.. DOC[epic="pki-doc"] - leerer String muss weg

RSA-Schlüsselpaar ohne echtes Passwort erzeugen (leerer String).

>>> priv_pem, _ = generate_rsa_key_pair(passphrase=None, key_size=2048)

Den Schlüssel als Objekt laden, um damit signieren zu können.

>>> key_obj = load_private_key_from_pem(priv_pem, passphrase=None)

Identität und Policy definieren

>>> subject = create_distinguished_name(
...     country="DE",
...     state="",
...     location="",
...     organization="Fitzz TeXnik Welt",
...     common_name="node-01.internal",
...     organizational_unit=""
... )
>>> policy = ClientServerPolicy()
>>> req = CertificateRequest(subject, policy)

Die Eingaben der SAN-Objecte kann vorab geprüft werden, um Fehler frühzeitig zu erkennen.
Wichtig um bei Passwordeingaben bei Fehlern vor der Passworteingabe abbrechen zu können,
um nicht mehrmals das Passwort eingeben zu müssen.

>>> req.verify_input_arguments(
...     dns_names=["node-01.internal"],
...     ip_addresses=["127.0.0.1"]
... ) 



CSR bauen.
Der Request benötigt das geladene Key-Objekt für die Signatur.

>>> _ = req.build(key_obj, dns_names=["service-01.internal"])

Ergebnis prüfen

>>> pem = req.get_pem()
>>> b"BEGIN CERTIFICATE REQUEST" in pem
True

Repräsentation
-----------------

Die String-Repräsentation erlaubt ein schnelles Debugging der Identität.

>>> req
CertificateRequest(subject=<Name(CN=node-01.internal,OU=,O=Fitzz TeXnik Welt,L=,ST=,C=DE)>)


Request speichern
--------------------


>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)



Um den CSR an eine CA zu übermitteln, speichern wir die PEM-Daten in eine Datei.
Hier nutzen wir die ``save_pem`` Utility aus dem Core-Modul.

>>> from ftwpki.baselibs.core import save_pem

>>> pki_dir = Path("cert_in/")
>>> csr_path = pki_dir / "node-01.csr"
>>> save_pem(pem, csr_path)

Überprüfung der Datei

>>> csr_path.exists()
True
>>> b"BEGIN CERTIFICATE REQUEST" in csr_path.read_bytes()
True

>>> env.clean_home()
>>> env.teardown()
