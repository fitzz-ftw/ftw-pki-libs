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

>>> config_path = user_config_path("ftwpki")
>>> config_path.as_posix() #doctest: +ELLIPSIS
'.../ftwpki'

>>> shared_data_path = user_data_path("ftwpki")
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

>> Path("~/.config/ftwpki/pkiconfig.toml").expanduser().exists()
>>> (config_path / "pkiconfig.toml").exists()
True

>> Path("~/.local/share/ftwpki/certs").expanduser().is_dir()
>>> (shared_data_path /"certs").is_dir()
True

>>> base_conf.private_keys
'~/.config/ftwpki/.private'

>>> base_conf.public_data
'~/.local/share/ftwpki'

>>> base_conf.certs
'~/.local/share/ftwpki/certs'

>>> base_conf.chains
'~/.local/share/ftwpki/chains'

>>> base_conf.ext_cert
'.crt'

>>> base_conf.ext_public
'.pub'

>>> base_conf.ext_signedcert
'.zip.enc'

>>> base_conf.resolve("test").as_posix()  #doctest: +ELLIPSIS
'.../testhome/testoutput/test'

>>> base_conf.resolve("test", "private_keys").as_posix()  #doctest: +ELLIPSIS
'.../.config/ftwpki/.private/test'

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


>>> from types import SimpleNamespace
>>> ro_pathes = base_conf.as_path(True)
>>> rw_pathes = base_conf.as_path(False)

>>> isinstance(ro_pathes, tuple)
True

>>> isinstance(rw_pathes, SimpleNamespace)
True

>>> ro_pathes.certs.as_posix() #doctest: +ELLIPSIS
'.../ftwpki/certs'

>>> ro_pathes.certs = Path("vorbidden/dir")
Traceback (most recent call last):
    ...
AttributeError: can't set attribute

>>> ro_pathes.certs == rw_pathes.certs
True

>>> rw_pathes.certs=Path("vorbidden/dir")
>>> ro_pathes.certs == rw_pathes.certs
False

>>> rw_pathes.certs.as_posix() #doctest: +ELLIPSIS
'vorbidden/dir'

>>> all([isinstance(i,Path) for i in rw_pathes])
True

>>> all([isinstance(i,Path) for i in ro_pathes])
True

.. !SECTION Test für CI entfernen Laufen nur auf Linux

>>> rw_pathes #doctest: +ELLIPSIS
PathContainerRW(...)

>>> ro_pathes #doctest: +ELLIPSIS
PathContainerRO(...)


>>> from ftwpki.baselibs.configuration import UserPKIConfig

>>> user_conf = UserPKIConfig()

file_name='user.toml'

>>> user_conf #doctest: +ELLIPSIS
UserPKIConfig(Path=.../ftwpki/user.toml)


>>> user_conf.as_path(False)
PathContainerRW(...)


>>> from ftwpki.baselibs.configuration import LeafPKIConfig

>>> leaf_conf= LeafPKIConfig()
>>> leaf_conf #doctest: +ELLIPSIS
LeafPKIConfig(Path=.../ftwpki/leaf.toml)

>>> leaf_conf.as_path()
PathContainerRO(...)

>>> from ftwpki.baselibs.configuration import RootSignerPKIConfig

>>> root_signer_conf= RootSignerPKIConfig()
>>> root_signer_conf #doctest: +ELLIPSIS
RootSignerPKIConfig(Path=.../ftwpki/rsign.toml)

>>> root_signer_conf.passphrases
'~/.config/ftwpki/.private'

>>> root_signer_conf.ext_chain
'.pem'

>>> root_signer_conf.as_path(False)
PathContainerRW(...)


>>> from ftwpki.baselibs.configuration import IntermedPKIConfig

>>> intermed_conf= IntermedPKIConfig()
>>> intermed_conf #doctest: +ELLIPSIS
IntermedPKIConfig(Path=.../ftwpki/intermed.toml)

>>> intermed_conf.policies
'~/.config/ftwpki/policies'

>>> intermed_conf.ext_policy
'.policy'

>>> intermed2_conf=IntermedPKIConfig()

>>> intermed2_conf.as_path()
PathContainerRO(...)


>>> env.clean_home()
>>> env.teardown()


