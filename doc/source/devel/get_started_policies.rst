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

>>> policy
RootPolicy()

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

>>> policy
IntermediatePolicy(path_length: 1)

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

>>> extensions = policy.get_extensions(dns_names=["api.fitzz.de", "internal.local"])

>>> san = next(ext for ext, _ in extensions if "SubjectAlternativeName" in str(type(ext)))
>>> [name.value for name in san]
['api.fitzz.de', 'internal.local']

>>> empty_ext= policy.get_extensions(dns_names=[])

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

>>> policy.get_extensions(dns_names=["org"])
Traceback (most recent call last):
    ...
ValueError: Hostname 'org' is not a FQDN (missing dot).

>>> policy.get_extensions(dns_names=["localhost"]) #doctest: +NORMALIZE_WHITESPACE +ELLIPSIS
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
 (<ExtendedKeyUsage([<ObjectIdentifier(oid=1.3.6.1.5.5.7.3.1, name=serverAuth)>])>, False), 
 (<SubjectAlternativeName(<GeneralNames([<DNSName(value='localhost')>])>)>, False)]

>>> policy.get_extensions(ip_addresses=["org"])
Traceback (most recent call last):
    ...
ValueError: 'org' does not appear to be an IPv4 or IPv6 address


2. Client-Identität (ClientPolicy)
----------------------------------

Bei mTLS dient der SAN-Eintrag zur Identifizierung des Clients am Server. 
Der CN im Subject ist hierbei nur zur Information für den Administrator.

>>> from ftwpki.baselibs.exceptions import PKIError # Falls benötigt
>>> from ftwpki.baselibs.policies import ClientPolicy
>>> policy = ClientPolicy()
>>> extensions = policy.get_extensions(dns_names=["machine-01.factory.internal"])

>>> san = next(ext for ext, _ in extensions if "SubjectAlternativeName" in str(type(ext)))
>>> san[0].value
'machine-01.factory.internal'

>>> empty_ext= policy.get_extensions(dns_names=[])

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



Kombinierte Identität (ClientServerPolicy)
-------------------------------------------

Wird verwendet, wenn ein Knoten sowohl als Client (mTLS) als auch als Server 
agiert. Auch hier ist das SAN-Feld technisch zwingend.

>>> from ftwpki.baselibs.policies import ClientServerPolicy
>>> policy = ClientServerPolicy()
>>> extensions = policy.get_extensions(dns_names=["node-7.cluster.local","192.168.20.4"])

>>> san = next(ext for ext, _ in extensions if "SubjectAlternativeName" in str(type(ext)))
>>> for item in san:
...     item.value
'node-7.cluster.local'
'192.168.20.4'

>>> empty_ext= policy.get_extensions(dns_names=[])


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
>>> from cryptography import x509
>>> dirname_entry = x509.Name([
...        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "DE"),
...        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Ftw-Pki Project"),
...        x509.NameAttribute(x509.NameOID.COMMON_NAME, "Client Server Node"),
...    ])

>>> san_ext={"emails": ["admin@example.org",], 
...     "dns_names": ["desktop-01.org",], 
...     "ip_addresses": ["192.168.20.1"],
...     "uris": ["https://example.org/profile#admin"],
...     "oids": [x509.ObjectIdentifier("1.2.3.4.5.6"),],
...     "directory_names": [dirname_entry],}

>>> from ftwpki.baselibs.policies import UserPolicy
>>> policy = UserPolicy()
>>> extensions = policy.get_extensions(**san_ext)


>>> san, _ = extensions[3]

Prüfung der unterschiedlichen Typen (RFC822 vs DNS)

>>> for name in san: # doctest: +NORMALIZE_WHITESPACE +ELLIPSIS
...     print(f"{type(name).__name__}: {name.value}")
DNSName: desktop-01.org
IPAddress: 192.168.20.1
RFC822Name: admin@example.org
UniformResourceIdentifier: https://example.org/profile#admin
RegisteredID: <ObjectIdentifier(oid=1.2.3.4.5.6, name=Unknown OID)>
DirectoryName: <Name(...)>

DirectoryName: <Name(C=DE,O=Ftw-Pki Project,CN=Client Server Node)>

>>> empty_ext= policy.get_extensions(ip_addresses=[])

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

