Get Stated with ConfigurationcClasses
======================================


>>> from pathlib import Path
>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)
>>> env.clean_home()

>>> from ftwpki.baselibs.configuration import BasePKIConfig

>>> from platformdirs import user_config_path, user_data_path

>>> config_path = user_config_path("ftwpki", "FitzzTeXnikWelt")
>>> config_path.as_posix() #doctest: +ELLIPSIS
'.../ftwpki'

>>> shared_data_path = user_data_path("ftwpki", "FitzzTeXnikWelt")
>>> shared_data_path.as_posix() #doctest: +ELLIPSIS
'.../ftwpki'


>>> BasePKIConfig("wrong.toml") #doctest: +ELLIPSIS
BasePKIConfig(Path=.../ftwpki/pkiconfig.toml)
>>> base_conf = BasePKIConfig(file_name="user.toml") 

>>> base_conf  #doctest: +ELLIPSIS
BasePKIConfig(Path=...ftwpki/pkiconfig.toml)

Linux:
/testhome/.config/ftwpki/pkiconfig.toml

Mac:
/testhome/Library/Application Support/ftwpki/pkiconfig.toml

Windows:
/testhome/AppData/Local/FitzzTeXnikWelt/ftwpki/pkiconfig.toml


>>> base_conf.init_completed()
{'set_config': False, 'set_filename': True, 'handel_pki_file': False}

>>> bool(base_conf)
False

>>> base_conf.set_config()


.. SECTION Test für CI entfernen Laufen nur auf Linux


>> for child in config_path.iterdir(): print(child)

>>> base_conf.config_path == config_path
True

>>> (config_path / "pkiconfig.toml").exists()
True

>>> base_conf.data_path == shared_data_path
True

>>> base_conf.private_key("ca.key.pem") #doctest: +ELLIPSIS
Traceback (most recent call last):
    ...
FileNotFoundError: [Errno 2] No such file or directory: '...ca.key.pem'

>> base_conf.


>>> base_conf.private_keys.as_posix() # doctest: +ELLIPSIS
'...ftwpki/.private'

>>> base_conf.public_data.as_posix() # doctest: +ELLIPSIS
'.../ftwpki'

>>> base_conf.get_certs() # doctest: +ELLIPSIS
{'ca.crt.pem': None, 'user.crt.pem': None, 'caroot.crt.pem': None}

>>> base_conf.fullchain # doctest: +ELLIPSIS
[]

>>> base_conf.resolve("test").as_posix()  #doctest: +ELLIPSIS
'.../testhome/testoutput/test'

>>> base_conf.resolve("test", "private_keys").as_posix()  #doctest: +ELLIPSIS
'.../ftwpki/.private/test'

Linux:
/testhome/.config/ftwpki/.private/test
Mac:
/testhome/Library/Application Support/ftwpki/pkiconfig.toml

Windows:
/testhome/AppData/Local/FitzzTeXnikWelt/ftwpki/pkiconfig.toml


>>> base_conf.resolve("./test", "private_keys").as_posix()  #doctest: +ELLIPSIS
'.../testhome/testoutput/test'

>>> base_conf.resolve("test", "wrong_name").as_posix()
Traceback (most recent call last):
    ...
KeyError: "Pfad-Kategorie 'wrong_name' nicht konfiguriert."

>>> base_conf.resolve("/opt/test", "wrong_name").as_posix() 
'/opt/test'

>>> base_conf.pki
PKIPackage()

.. !SECTION Test für CI entfernen Laufen nur auf Linux

>>> base_conf.current_configfile_entries # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
{'private_keys': '#config#.private', 
 'zip': '#data#', 
 'certs': '#zip#', 
 'chains': '#zip#', 
 'config_path': '#config#', 
 'data_path': '#data#'}

>>> base_conf.set_config()



>>> from ftwpki.baselibs.configuration import UserPKIConfig

>>> user_conf = UserPKIConfig()

file_name='user.toml'

>>> user_conf #doctest: +ELLIPSIS
UserPKIConfig(Path=.../ftwpki/pkiconfig.toml)




>>> from ftwpki.baselibs.configuration import LeafPKIConfig

>>> leaf_conf= LeafPKIConfig()
>>> leaf_conf #doctest: +ELLIPSIS
LeafPKIConfig(Path=.../ftwpki/pkiconfig.toml)

>>> root_pki= env.copy2cwd("tests_pki_root/ca_root.pki", "ca_root.pki")

>>> from ftwpki.baselibs.configuration import RootSignerPKIConfig

>>> root_signer_conf= RootSignerPKIConfig("ca_root.pki")
>>> root_signer_conf #doctest: +ELLIPSIS
RootSignerPKIConfig(Path=.../ftwpki/pkiconfig.toml)

>>> root_signer_conf.passphrases.as_posix()  #doctest: +ELLIPSIS
'.../ftwpki/.private'

>>> root_signer_conf.fullchain
[]

>>> root_signer_conf.handle_pki_file()

>>> root_signer_conf.fullchain #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
[<Certificate(subject=<Name(...CN=Muster-Verband Bundesverband Root CA...)>, ...)>, 
 <Certificate(subject=<Name(...CN=Muster-Verband Bundesverband Root CA...)>, ...)>]

>>> root_signer_conf.handle_pki_file()

>>> root_signer_conf.own_cert #doctest: +ELLIPSIS 
<Certificate(subject=<Name(...CN=Muster-Verband Bundesverband Root CA...)>, ...)>

>>> root_signer_conf.private_key("caroot.key.pem") #doctest: +ELLIPSIS 
b'-----BEGIN ENCRYPTED PRIVATE KEY----...


>>> root_signer_conf.policy_files
['ca_root.policy']

>>> root_signer_conf.get_dn_policies(  #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
...     policyname='ca_root.policy', 
...     section = "intermediate")
{'countryName': 'match', 
 'organizationName': 'match', 
 'commonName': 'supplied', 
 'localityName': 'supplied', 
 'organizationalUnitName': 'optional', 
 'stateOrProvinceName': 'optional'}

>>> root_signer_conf.get_extentions(  #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
...     policyname='ca_root.policy', 
...     section = "intermediate")
{'ocspURI': 'http://ocsp.example.org/root', 
 'crlURI': 'http://pki.example.org/rsm/regional.crl', 
 'caIssuerURI': 'http://pki.example.org/root/root.crt'}

>>> root_pki= env.copy2cwd("tests_pki_root/ca_root_wop.pki", "ca_root_wop.pki")

>>> root_wop_conf= RootSignerPKIConfig("ca_root_wop.pki", section="")

>>> root_wop_conf.handle_pki_file()

>>> root_wop_conf.in_zip
['certs', 'chains']

>>> root_wop_conf.private_key("not_there.key.pem") #doctest: +ELLIPSIS 
Traceback (most recent call last):
    ...
FileNotFoundError: [Errno 2] No such file or directory: '...not_there.key.pem'


>>> from ftwpki.baselibs.configuration import IntermedPKIConfig

>>> intermed_conf= IntermedPKIConfig()
>>> intermed_conf #doctest: +ELLIPSIS
IntermedPKIConfig(Path=.../ftwpki/pkiconfig.toml)

>>> intermed_conf.policies.as_posix()  #doctest: +ELLIPSIS
'.../ftwpki/.private'

>>> intermed_conf.ext_policy
'.policy'

>>> intermed2_conf=IntermedPKIConfig()


>> env.clean_home()
>>> env.teardown()


