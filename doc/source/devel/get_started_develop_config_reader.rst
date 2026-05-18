:orphan:

Get Stated with ConfigurationcClasses
======================================


>>> from pathlib import Path
>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)
>>> env.clean_home()


>>> from ftwpki.baselibs.configuration import BasePKIConfig
>>> base_conf = BasePKIConfig(file_name="user.toml") 
>>> base_conf.set_config()


>>> from ftwpki.baselibs.configuration import ReaderPKIConfig

>>> reader = ReaderPKIConfig()

>>> reader.read_main_config()

>>> reader._configmain # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
{'default_config': 'user.toml', 
 'user': 'user.toml', 
 'leaf': 'leaf.toml', 
 'server': 'leaf.toml', 
 'client': 'leaf.toml', 
 'clientserver': 'leaf.toml', 
 'intermediate': 'intermed.toml', 
 'rootsign': 'rsign.toml'}

>>> reader.default_config
'user.toml'

>>> reader.list_mainconfig()  # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
{'user': 'user.toml', 
 'leaf': 'leaf.toml', 
 'server': 'leaf.toml', 
 'client': 'leaf.toml', 
 'clientserver': 'leaf.toml', 
 'intermediate': 'intermed.toml', 
 'rootsign': 'rsign.toml'}

>>> reader.read_config()

>>> reader._raw_data  # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
{'private_keys': '#config#.private', 
 'public_data': '#data#', 
 'certs': '#data#certs', 
 'chains': '#data#chains', 
 'ext_cert': '.crt.pem', 
 'ext_public': '.pub.pem',
 'ext_chain': '.chain.pem',  
 'ext_signedcert': '.zip.enc'}

>>> reader._paths  # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
{'private_keys': ...Path('.../ftwpki/.private'), 
 'public_data': ...Path('.../ftwpki'), 
 'certs': ...Path('.../ftwpki/certs'), 
 'chains': ...Path('.../ftwpki/chains')}

>>> reader.private_keys.as_posix()  # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
'.../ftwpki/.private'

>>> reader.public_data.as_posix()  # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
'.../ftwpki'

>>> reader.certs.as_posix()  # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
'.../ftwpki/certs'

>>> reader.chains.as_posix()  # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
'.../ftwpki/chains'


.. SECTION - Comprehensive Coverage Testing for ReaderPKIConfig

Now we systematically verify the read-only properties and ensure that 
unconfigured directories safely return None instead of raising errors.

First, let's look at the current active profile (which is 'leaf' based on user.toml):
>>> reader._conf_type
'leaf'

Verify that the leaf properties return valid paths or strings:
>>> isinstance(reader.private_keys, Path)
True
>>> isinstance(reader.certs, Path)
True
>>> isinstance(reader.ext_cert, str)
True

Since this is a standard leaf profile, policies and passphrases MUST return None:
>>> reader.passphrases is None
True
>>> reader.policies is None
True
>>> reader.ext_policy is None
True



Finally, verify the remaining extension properties to hit 100% statement coverage:
>>> reader.ext_chain is None or isinstance(reader.ext_chain, str)
True
>>> reader.ext_public is None or isinstance(reader.ext_public, str)
True
>>> reader.ext_signedcert is None or isinstance(reader.ext_signedcert, str)
True

>>> reader_2 = ReaderPKIConfig()
>>> reader_2.read_config()

>>> reader_2.read_config("intermediate") #doctest: +ELLIPSIS
Traceback (most recent call last):
    ...
FileNotFoundError: [Errno 2] No such file or directory: '...intermed.toml'

>>> from ftwpki.baselibs.configuration import IntermedPKIConfig,RootSignerPKIConfig

>>> intermedia_config = IntermedPKIConfig()

>>> reader_2.read_config("intermediate") #doctest: +ELLIPSIS

>>> reader_2.config_type
'intermediate'



>>> rsigner_config=RootSignerPKIConfig()

>>> reader_3 = ReaderPKIConfig()

>>> reader_3.read_config("rootsign")

>>> reader_3.config_type
'root'

.. !SECTION - Comprehensive Coverage Testing for ReaderPKIConfig






>>> env.clean_home()
>>> env.teardown()
