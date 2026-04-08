Get Started: PKI Policies
=========================

Policies definieren die technischen Einschränkungen und Erweiterungen (Extensions) 
eines Zertifikats. Sie bestimmen, ob ein Zertifikat eine CA ist oder wofür 
es verwendet werden darf (z. B. Server-Auth).

Root-CA Policy (RootPolicy)
------------------------------

Die ``RootPolicy`` setzt die grundlegenden Berechtigungen für eine Stamm-Zertifizierungsstelle.

>>> from ftwpki.baselibs.policies import RootPolicy
>>> policy = RootPolicy()
>>> extensions = policy.get_extensions()

Prüfung der Basic Constraints (CA: True, Path Length: None)

>>> bc, critical = extensions[0]
>>> bc.ca
True
>>> critical
True

Intermediate-CA Policy (IntermediatePolicy)
----------------------------------------------

Bei Intermediates ist die ``path_length`` entscheidend, um die Tiefe der 
Zertifikatskette zu begrenzen.

>>> from ftwpki.baselibs.policies import IntermediatePolicy

Erlaubt noch eine weitere CA-Ebene

>>> policy = IntermediatePolicy(path_length=1)
>>> extensions = policy.get_extensions()

>>> bc, _ = extensions[0]
>>> bc.path_length
1


Server-Identität (ServerPolicy)
----------------------------------

Für TLS-Server müssen alle DNS-Namen, unter denen der Dienst erreichbar ist, 
als SAN hinterlegt sein.

>>> from ftwpki.baselibs.policies import ServerPolicy
>>> policy = ServerPolicy()

Wichtig: Ohne diese Liste schlägt der Browser/Client-Check fehl

>>> extensions = policy.get_extensions(alt_names=["api.fitzz.de", "internal.local"])

>>> san = next(ext for ext, _ in extensions if "SubjectAlternativeName" in str(type(ext)))
>>> [name.value for name in san]
['api.fitzz.de', 'internal.local']

>>> empty_ext= policy.get_extensions(alt_names=[])

>>> empty_ext # doctest: +NORMALIZE_WHITESPACE +ELLIPSIS
[(<BasicConstraints(ca=False, path_length=None)>, True), 
 (<KeyUsage(digital_signature=True, 
            content_commitment=False, 
            key_encipherment=True, 
            data_encipherment=False, 
            key_agreement=False, 
            key_cert_sign=False, 
            crl_sign=False, 
            encipher_only=False, 
            decipher_only=False)>, True), 
 (<ExtendedKeyUsage([<ObjectIdentifier(oid=1.3.6.1.5.5.7.3.1, name=serverAuth)>])>, False)]

>>> any("SubjectAlternativeName" in str(type(ext)) for ext, _ in empty_ext)
False




2. Client-Identität (ClientPolicy)
----------------------------------

Bei mTLS dient der SAN-Eintrag zur Identifizierung des Clients am Server. 
Der CN im Subject ist hierbei nur zur Information für den Administrator.

>>> from ftwpki.baselibs.exceptions import PKIError # Falls benötigt
>>> from ftwpki.baselibs.policies import ClientPolicy
>>> policy = ClientPolicy()
>>> extensions = policy.get_extensions(alt_names=["machine-01.factory.internal"])

>>> san = next(ext for ext, _ in extensions if "SubjectAlternativeName" in str(type(ext)))
>>> san[0].value
'machine-01.factory.internal'

>>> empty_ext= policy.get_extensions(alt_names=[])

>>> empty_ext # doctest: +NORMALIZE_WHITESPACE +ELLIPSIS
[(<BasicConstraints(ca=False, path_length=None)>, True), 
 (<KeyUsage(digital_signature=True, 
            content_commitment=False, 
            key_encipherment=True, 
            data_encipherment=False, 
            key_agreement=False, 
            key_cert_sign=False, 
            crl_sign=False, 
            encipher_only=False, 
            decipher_only=False)>, True), 
 (<ExtendedKeyUsage([<ObjectIdentifier(oid=1.3.6.1.5.5.7.3.2, name=clientAuth)>])>, False)]

>>> any("SubjectAlternativeName" in str(type(ext)) for ext, _ in empty_ext)
False



Kombinierte Identität (StandalonePolicy)
-------------------------------------------

Wird verwendet, wenn ein Knoten sowohl als Client (mTLS) als auch als Server 
agiert. Auch hier ist das SAN-Feld technisch zwingend.

>>> from ftwpki.baselibs.policies import StandalonePolicy
>>> policy = StandalonePolicy()
>>> extensions = policy.get_extensions(alt_names=["node-7.cluster.local","192.168.20.4"])

>>> san = next(ext for ext, _ in extensions if "SubjectAlternativeName" in str(type(ext)))
>>> for item in san:
...     item.value
'node-7.cluster.local'
'192.168.20.4'

>>> empty_ext= policy.get_extensions(alt_names=[])


>>> empty_ext # doctest: +NORMALIZE_WHITESPACE +ELLIPSIS
[(<BasicConstraints(ca=False, path_length=None)>, True), 
 (<KeyUsage(digital_signature=True, 
            content_commitment=False, 
            key_encipherment=True, 
            data_encipherment=False, 
            key_agreement=False, 
            key_cert_sign=False, 
            crl_sign=False, 
            encipher_only=False, 
            decipher_only=False)>, True), 
 (<ExtendedKeyUsage([<ObjectIdentifier(oid=1.3.6.1.5.5.7.3.1, name=serverAuth)>,
                    <ObjectIdentifier(oid=1.3.6.1.5.5.7.3.2, name=clientAuth)>])>, False)]

>>> any("SubjectAlternativeName" in str(type(ext)) for ext, _ in empty_ext)
False


User-Zertifikate (UserPolicy)
--------------------------------

User-Policies unterscheiden zwischen DNS-Namen und E-Mail-Adressen (RFC822Name).

>>> from ftwpki.baselibs.policies import UserPolicy
>>> policy = UserPolicy()
>>> extensions = policy.get_extensions(alt_names=["admin@example.org", "desktop-01","192.168.20.*"])

>>> san, _ = extensions[3]

Prüfung der unterschiedlichen Typen (RFC822 vs DNS)

>>> for name in san:
...     print(f"{type(name).__name__}: {name.value}")
RFC822Name: admin@example.org
DNSName: desktop-01
DNSName: 192.168.20.*


>>> empty_ext= policy.get_extensions(alt_names=[])

>>> empty_ext # doctest: +NORMALIZE_WHITESPACE +ELLIPSIS
[(<BasicConstraints(ca=False, path_length=None)>, True), 
 (<KeyUsage(digital_signature=True, 
            content_commitment=True, 
            key_encipherment=True, 
            data_encipherment=True, 
            key_agreement=False, 
            key_cert_sign=False, 
            crl_sign=False, 
            encipher_only=False, 
            decipher_only=False)>, True), 
 (<ExtendedKeyUsage([<ObjectIdentifier(oid=1.3.6.1.5.5.7.3.2, name=clientAuth)>, 
                     <ObjectIdentifier(oid=1.3.6.1.5.5.7.3.4, name=emailProtection)>, 
                     <ObjectIdentifier(oid=1.3.6.1.5.5.7.3.3, name=codeSigning)>])>, False)]

>>> any("SubjectAlternativeName" in str(type(ext)) for ext, _ in empty_ext)
False

