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




>>> base_conf = BasePKIConfig() 
file_name=None

>>> base_conf  #doctest: +ELLIPSIS
BasePKIConfig(Path=...ftwpki/pkiconfig.toml)

Linux:
/testhome/.config/ftwpki/pkiconfig.toml

Mac:
/testhome/Library/Application Support/ftwpki/pkiconfig.toml

Windows:
/testhome/AppData/Local/FitzzTeXnikWelt/ftwpki/pkiconfig.toml




>>> base_conf.set_config()

.. SECTION Test für CI entfernen Laufen nur auf Linux


>> for child in config_path.iterdir(): print(child)


>>> (config_path / "pkiconfig.toml").exists()
True


>>> (shared_data_path /"certs").exists()
True

>>> (shared_data_path /"certs").is_dir()
True

>>> base_conf.private_keys.as_posix() # doctest: +ELLIPSIS
'...ftwpki/.private'

>>> base_conf.public_data.as_posix() # doctest: +ELLIPSIS
'.../ftwpki'

>>> base_conf.certs.as_posix() # doctest: +ELLIPSIS
'.../ftwpki/certs'

>>> base_conf.chains.as_posix() # doctest: +ELLIPSIS
'.../ftwpki/chains'

>>> base_conf.ext_cert
'.crt'

>>> base_conf.ext_public
'.pub'

>>> base_conf.ext_signedcert
'.zip.enc'

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


.. !SECTION Test für CI entfernen Laufen nur auf Linux

>>> base_conf.current_configfile_entries # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
{'private_keys': '#config#.private', 
 'passphrases': '#config#.private', 
 'csr_configs': '#config#csr', 
 'policies': '#config#policies', 
 'public_data': '#data#', 
 'certs': '#data#certs', 
 'chains': '#data#/chains', 
 'ext_cert': '.crt', 
 'ext_public': '.pub', 
 'ext_chain': '.pem', 
 'ext_csr_conf': '.toml', 
 'ext_policy': '.policy', 
 'ext_signedcert': '.zip.enc'}


>>> from ftwpki.baselibs.configuration import UserPKIConfig

>>> user_conf = UserPKIConfig()

file_name='user.toml'

>>> user_conf #doctest: +ELLIPSIS
UserPKIConfig(Path=.../ftwpki/user.toml)




>>> from ftwpki.baselibs.configuration import LeafPKIConfig

>>> leaf_conf= LeafPKIConfig()
>>> leaf_conf #doctest: +ELLIPSIS
LeafPKIConfig(Path=.../ftwpki/leaf.toml)


>>> from ftwpki.baselibs.configuration import RootSignerPKIConfig

>>> root_signer_conf= RootSignerPKIConfig()
>>> root_signer_conf #doctest: +ELLIPSIS
RootSignerPKIConfig(Path=.../ftwpki/rsign.toml)

>>> root_signer_conf.passphrases.as_posix()  #doctest: +ELLIPSIS
'.../ftwpki/.private'

>>> root_signer_conf.ext_chain
'.pem'



>>> from ftwpki.baselibs.configuration import IntermedPKIConfig

>>> intermed_conf= IntermedPKIConfig()
>>> intermed_conf #doctest: +ELLIPSIS
IntermedPKIConfig(Path=.../ftwpki/intermed.toml)

>>> intermed_conf.policies.as_posix()  #doctest: +ELLIPSIS
'.../ftwpki/policies'

>>> intermed_conf.ext_policy
'.policy'

>>> intermed2_conf=IntermedPKIConfig()



>>> env.clean_home()
>>> env.teardown()


