


>>> from fitzzftw.develtool.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)



>>> from ftwpki.baselibs.toml_utils import toml2dn

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

>>> from ftwpki.baselibs.toml_utils import list_policy_sections

>>> data={"server":{"dn":""},"intermediate":{"dn"}, "clientsecure":{"dn"}, "client":{"san"}}
>>> list_policy_sections(data, "dn")
server
intermediate
clientsecure
True

>>> from ftwpki.baselibs.toml_utils import toml2dn_policy
>>> _ = env.copy2cwd("toml_2_dn_test.toml")
>>> argv=["--conf_file", "toml_2_dn_test.toml"]

>> toml2dn_policy(argv)
intermediate
server
user
server_l2
{'commonName': 'error'}

>>> argv=["--conf_file", "toml_2_dn_test.toml", "--policy-name", "intermediate"]
>>> toml2dn_policy(argv)
{'countryName': 'match', 'organizationName': 'match', 'commonName': 'supplied'}

>>> toml2dn_policy(filename="toml_2_dn_test.toml", section="server") #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
{'countryName': 'match', 
 'organizationName': 'match', 
 'organizationalUnitName': 'supplied', 
 'commonName': 'supplied'}

>>> toml2dn_policy()
{}

>>> toml2dn_policy(filename="toml_2_dn_test.toml")
intermediate
server
user
server_l2
{'commonName': 'error'}

>>> toml2dn_policy(filename="not_exists.toml")
Error loading TOML 'not_exists.toml': [Errno 2] No such file or directory: 'not_exists.toml'
{}

>>> toml2dn_policy(filename="toml_2_dn_test.toml", section="secureintermediate") #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
{}

>>> env.teardown()
