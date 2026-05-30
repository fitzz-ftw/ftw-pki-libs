Using the Package Module
==========================

Setup Environment
------------------

.. SECTION - Setup Environment

>>> test_data_pre= "test_ok_data"
>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"),
...     appname="ftwpki", appauthor="FitzzTeXnikWelt")
>>> env.setup(True)
>>> env.clean_output()

.. !SECTION - Setup Environment

Preparation
-----------
>>> ca_key_path = env.copy2cwd(f"{test_data_pre}/.private/ca.key.pem",
...             "ca.key.pem")
>>> ca_passphrase_path = env.copy2cwd(f"{test_data_pre}/.private/carootsecret",
...             "carootsecret")
>>> ca_cert_path = env.copy2cwd(f"{test_data_pre}/ca.crt.pem",
...             "ca.crt.pem")


>>> cert_path = env.copy2cwd(f"{test_data_pre}/Muster-Verband-Hamburg-Regional-CA_Hamburg.crt.pem",
...             "Muster-Verband-Hamburg-Regional-CA_Hamburg.crt.pem")

>>> cert_name = cert_path.name

>>> cert_name
'Muster-Verband-Hamburg-Regional-CA_Hamburg.crt.pem'

>>> def getpasswd(prompt:str)->str:
...     return "secret"

>>> from ftwpki.baselibs.passwd import PasswordManager
>>> pwd_man = PasswordManager(private_dir="")


>>> ca_key_passphrase  = pwd_man.decrypt_password_file(ca_passphrase_path, getpasswd("Enter Password:"))

>> ca_key_passphrase

>>> from ftwpki.baselibs.core import (
...     load_private_key_from_pem,
...     load_certificate_from_pem,
...     )

>>> ca_key= load_private_key_from_pem(
...             pem_data = ca_key_path.read_bytes(), 
...             passphrase=ca_key_passphrase)

>>> ca_cert = load_certificate_from_pem(ca_cert_path.read_bytes())

>> ca_cert

>>> cert = load_certificate_from_pem(cert_path.read_bytes())

>> cert 

>>> from ftwpki.baselibs.package import PKIPackage

>>> pki_pack = PKIPackage()

>>> pki_pack
PKIPackage()


>>> pki_pack.private_key
Traceback (most recent call last):
    ...
ValueError: PKIPackage: Private Key wurde noch nicht zugewiesen.


>>> pki_pack.recipient_cert=cert
>>> pki_pack.caroot_cert=ca_cert
>>> pki_pack.private_key=ca_key
>>> pki_pack.ca_cert=ca_cert

>>> pki_pack.recipient_cert=cert

>>> pki_pack.recipient_cert #doctest: +NORMALIZE_WHITESPACE +ELLIPSIS
<Certificate(subject=<Name(...CN=Muster-Verband Hamburg Regional CA...)>, ...)>

>>> pki_pack.caroot_cert #doctest: +NORMALIZE_WHITESPACE +ELLIPSIS
<Certificate(subject=<Name(...CN=Muster-Verband Bundesverband Root CA...)>, ...)>


>>> pki_pack.private_key #doctest: +NORMALIZE_WHITESPACE +ELLIPSIS
<cryptography.hazmat.bindings._rust.openssl.rsa.RSAPrivateKey object at 0x...>

>>> pki_pack.ca_cert #doctest: +NORMALIZE_WHITESPACE +ELLIPSIS
<Certificate(subject=<Name(...CN=Muster-Verband Bundesverband Root CA...)>, ...)>

>>> pki_pack.to_encrypt
False


>>> pki_pack.additional_files
{}

>>> readme_path = env.copy2cwd(f"{test_data_pre}/README.txt",
...             "README.md")

>>> changelog_path = env.copy2cwd(f"{test_data_pre}/CHANGELOG.txt",
...             "CHANGELOG.md")

>>> pki_pack.additional_files["readme.md"] = readme_path.read_bytes()

>>> pki_pack.additional_files["changelog.md"] = changelog_path.read_bytes()

>>> pki_pack.additional_files["old_changelog.md"] = changelog_path.read_bytes()


>>> pki_pack.additional_files.keys()
dict_keys(['readme.md', 'changelog.md', 'old_changelog.md'])

>>> del pki_pack.additional_files["old_changelog.md"]

>>> pki_pack.additional_files.keys()
dict_keys(['readme.md', 'changelog.md'])



>>> pki_pack.save()
Traceback (most recent call last):
    ...
ValueError: Kein Pfad zum Speichern angegeben.

>>> pki_path = pki_pack.save("reg_hh.zip")

>>> Path("reg_hh.pki").is_file()
True

>>> pki_pack.to_encrypt = True

>>> pki_pack.message = "Here is your signed certificate."

>>> pack_path = pki_pack.save("reg_hh.zip")

>>> Path("reg_hh.spki").is_file()
True


>>> pki_read = PKIPackage()

>>> pki_read.load("reg_hh.pki")

>>> pki_read.private_key
Traceback (most recent call last):
    ...
ValueError: PKIPackage: Private Key wurde noch nicht zugewiesen.

>>> pki_read.recipient_cert #doctest: +NORMALIZE_WHITESPACE +ELLIPSIS
<Certificate(subject=<Name(...CN=Muster-Verband Hamburg Regional CA...)>, ...)>

>>> pki_read._intermediate_certs #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
[<Certificate(subject=<Name(...CN=Muster-Verband Hamburg Regional CA...)>, ...)>, 
<Certificate(subject=<Name(...CN=Muster-Verband Bundesverband Root CA...)>, ...)>]

>>> pki_read.recipient_cert #doctest: +NORMALIZE_WHITESPACE +ELLIPSIS
<Certificate(subject=<Name(...CN=Muster-Verband Hamburg Regional CA...)>, ...)>


>>> pki_read.caroot_cert #doctest: +NORMALIZE_WHITESPACE +ELLIPSIS
<Certificate(subject=<Name(...CN=Muster-Verband Bundesverband Root CA...)>, ...)>


Loading an encrypted Package (.spki)

>>> recip_key_path = env.copy2cwd(f"{test_data_pre}/.private_recip/intermed1.key.pem",
...             "intermed1.key.pem")
>>> recip_passphrase_path = env.copy2cwd(f"{test_data_pre}/.private_recip/inter1secret",
...             "inter1secret")

>>> recip_pwd_man = PasswordManager(private_dir="")

>>> recip_key_passphrase  = pwd_man.decrypt_password_file(recip_passphrase_path, getpasswd("Enter Password:"))
>>> recip_key= load_private_key_from_pem(
...             pem_data = recip_key_path.read_bytes(), 
...             passphrase=recip_key_passphrase)

>>> recip_pack = PKIPackage()
>>> recip_pack.has_private_key
False

>>> recip_pack.load("reg_hh.spki")
Traceback (most recent call last):
    ...
AttributeError: 'NoneType' object has no attribute 'public_key'

>>> recip_pack.private_key = recip_key

>>> recip_pack.has_private_key
True

>>> recip_pack.load("reg_hh.spki")

>>> recip_pack.message
'Here is your signed certificate.'

>>> del recip_pack.message

>>> recip_pack.message
''
>>> recip_pack.additional_files.keys()
dict_keys(['readme.md', 'changelog.md'])

>>> recip_pack.additional_files["readme.md"] == readme_path.read_bytes()
True



>>> del recip_pack.additional_files

>>> recip_pack.additional_files
{}

>>> recip_pack.to_encrypt
True

>>> recip_pack.to_encrypt = False

>>> pack_path = recip_pack.save("local_use.zip")



..SECTION - Teardown Environment

>>> env.clean_home()
>>> env.teardown()

..!SECTION - Teardown Environment
