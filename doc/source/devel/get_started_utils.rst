


>>> from fitzzftw.develtool.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)



>>> from ftwpki.baselibs.utils import toml2dn

>>> toml2dn([])
{}

>>> toml2dn(["--conf_file", "not_there.toml"])
File 'not_there.toml' not found!
{'dnsubject': ''}


>>> conf_ca = env.copy2cwd("toml_2_dn_test.toml", "ca_conf.toml" )
>>> conf_ca.name
'ca_conf.toml'

>>> toml2dn(["--conf_file", conf_ca.name]) # doctest: +NORMALIZE_WHITESPACE
{'countryName': 'DE', 
 'organizationName': 'Fitzz TeXnik Welt', 
 'commonName': 'Fitzz Root CA', 
 'dnsubject': ''}

>>> conf_keyerror = env.copy2cwd("toml_2_dn_keyerror.toml", "ca_keyerror.toml" )
>>> toml2dn(["--conf_file", conf_keyerror.name])
No table 'identity.dn' in config file!
{'dnsubject': ''}

>>> conf_dec_error = env.copy2cwd("toml_decode_error.txt", "ca_decode_error.toml" )
>>> toml2dn(["--conf_file", conf_dec_error.name])
Could not decode file ca_decode_error.toml!
{'dnsubject': ''}

>>> toml2dn()
{}


>>> env.teardown()
