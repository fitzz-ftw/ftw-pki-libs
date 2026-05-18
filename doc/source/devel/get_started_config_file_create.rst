Configuration File Creating
============================

>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)
>>> env.clean_home()


>>> from ftwpki.baselibs.config_file_create import toml_conf_str, write_example_config

>>> write_example_config(toml_conf_str)
>>> write_example_config(toml_conf_str)
>>> from ftwpki.baselibs.app_dirs import PKIDirs
>>> conf_file = PKIDirs().user_config_path / "pkiconfig.toml"

>>> conf_file.is_file()
True

>>> print(conf_file.read_text()) # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE 
<BLANKLINE>
[fallback]
# Identity (encrypted & hidden)
private_keys = "#config#.private"
passphrases  = "#config#.private"
<BLANKLINE>
# Infrastructure resources
csr_configs  = "#config#csr"
policies     = "#config#policies"
<BLANKLINE>
# Public data
public_data  = "#data#"
certs        = "#data#certs"
chains       = "#data#/chains"
<BLANKLINE>
# File extensions for public/semi-private data only
ext_cert     = ".crt.pem"
ext_public   = ".pub.pem"
ext_chain    = ".chain.pem"
ext_csr_conf = ".toml"
ext_policy   = ".policy"
ext_signedcert= ".zip.enc"
<BLANKLINE>
[intermediate]
# Overrides paths for intermediate-specific rules if needed
policies     = "#config#/policies/intermediate"
<BLANKLINE>
<BLANKLINE>



>>> conf_file.unlink()

>>> from ftwpki.baselibs.config_file_create import MAIN_CONFIG

conf_file2 = PKIDirs().user_config_path / "pkiconfig.toml"
>>> content = MAIN_CONFIG.format(file_name="user.toml")

>>> write_example_config(content)

>>> conf_file.is_file()
True

>>> print(conf_file.read_text()) # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE 
<BLANKLINE>
[fallback]
default_config="user.toml"
user = "user.toml"
leaf="leaf.toml"
server="leaf.toml"
client="leaf.toml"
clientserver="leaf.toml"
intermediate = "intermed.toml"
rootsign = "rsign.toml"
<BLANKLINE>
<BLANKLINE>



>>> env.clean_home()
>>> env.teardown()
