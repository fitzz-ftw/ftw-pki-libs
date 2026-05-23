Utilities for TOML
===================


>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)



>>> from ftwpki.baselibs.toml_utils import toml2dn

>>> from ftwpki.baselibs.cli_parser import TomlPreParser

>>> pre_parser = TomlPreParser()


>>> toml2dn(None)
{}

>>> argv, _ = pre_parser.parse_known_args(["--conf-file", "not_there.toml"])
>>> toml2dn(argv.conf_file)
File 'not_there.toml' not found!
{'dnsubject': ''}


>>> conf_ca = env.copy2cwd("toml_2_dn_test.toml", "ca_conf.toml" )
>>> conf_ca.name
'ca_conf.toml'

>>> argv, _ = pre_parser.parse_known_args(["--conf-file", conf_ca.name])
>>> toml2dn(argv.conf_file) # doctest: +NORMALIZE_WHITESPACE
{'countryName': 'DE', 
 'organizationName': 'Fitzz TeXnik Welt', 
 'commonName': 'Fitzz Root CA', 
 'dnsubject': ''}

>>> conf_keyerror = env.copy2cwd("toml_2_dn_keyerror.toml", "ca_keyerror.toml" )
>>> argv, _ = pre_parser.parse_known_args(["--conf-file", conf_keyerror.name])
>>> toml2dn(argv.conf_file)
No table 'identity.dn' in config file!
{'dnsubject': ''}

>>> conf_dec_error = env.copy2cwd("toml_decode_error.txt", "ca_decode_error.toml" )
>>> argv, _ = pre_parser.parse_known_args(["--conf-file", conf_dec_error.name])
>>> toml2dn(argv.conf_file)
Could not decode file ca_decode_error.toml!
{'dnsubject': ''}


>>> from ftwpki.baselibs.toml_utils import list_policy_sections

>>> data={"server":{"dn":""},"intermediate":{"dn"}, "clientsecure":{"dn"}, "client":{"san"}}
>>> list_policy_sections(data, "dn")
server
intermediate
clientsecure
True

>>> from ftwpki.baselibs.toml_utils import toml2dn_policy
>>> _ = env.copy2cwd("toml_2_dn_test.toml")
>>> argv,_ = pre_parser.parse_known_args(["--conf-file", "toml_2_dn_test.toml"])

>>> toml2dn_policy(argv.conf_file)
intermediate
server
user
server_l2
{'commonName': 'error'}

>>> argv=["--conf-file", "toml_2_dn_test.toml", "--policy-name", "intermediate"]
>>> pre_args , _ = pre_parser.parse_known_args(argv)


>>> toml2dn_policy(pre_args.conf_file, pre_args.policy_name) # doctest: +ELLIPSIS   
{'countryName': 'match', 'organizationName': 'match', 'commonName': 'supplied'}

>>> toml2dn_policy("toml_2_dn_test.toml", "server") #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
{'countryName': 'match', 
 'organizationName': 'match', 
 'organizationalUnitName': 'supplied', 
 'commonName': 'supplied'}


>>> toml2dn_policy(None,'') # doctest: +ELLIPSIS   
{}

>>> toml2dn_policy(filename="toml_2_dn_test.toml") # doctest: +ELLIPSIS   
intermediate
server
user
server_l2
{'commonName': 'error'}

>>> toml2dn_policy(filename="not_exists.toml") # doctest: +ELLIPSIS   
Error loading TOML 'not_exists.toml': [Errno 2] No such file or directory: 'not_exists.toml'
{}

>>> toml2dn_policy("toml_2_dn_test.toml", "secureintermediate") #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
{}

>>> from ftwpki.baselibs.toml_utils import toml2ext

>>> ext_only_toml=env.copy2cwd("toml_2_ext_test_only.toml")

>>> toml2ext(filename="toml_2_ext_test_only.toml")
secureintermediate
{'commonName': 'error'}

>>> toml2ext(filename="toml_2_ext_test_only.toml", section="intermediate") #doctest: +NORMALIZE_WHITESPACE
{'ocspURI': 'http://ocsp.deine-pki.test', 
 'crlURI': 'http://pki.deine-pki.test/crl', 
 'caIssuerURI': 'http://pki.deine-pki.test/ca.crt'}

>>> toml2ext(filename="toml_2_ext_test_only.toml", section="secureintermediate") #doctest: +NORMALIZE_WHITESPACE
{'ocspURI': 'http://ocsp.deine-pki.test', 
 'crlURI': 'http://pki.deine-pki.test/crl_intermediate', 
 'caIssuerURI': 'http://pki.deine-pki.test/ca.crt'}

>>> from ftwpki.baselibs.config_file_create import toml_conf_str, write_example_config
>>> write_example_config(toml_conf_str)

>> env.teardown()
>> print("Stop")

>>> from ftwpki.baselibs.toml_utils import toml2config

>>> toml2config() #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
{'private_keys': '#config#.private', 
 'passphrases': '#config#.private', 
 'csr_configs': '#config#csr', 
 'policies': '#config#policies', 
 'public_data': '#data#', 
 'certs': '#data#certs', 
 'chains': '#data#/chains', 
 'ext_cert': '.crt.pem', 
 'ext_public': '.pub.pem', 
 'ext_chain': '.chain.pem', 
 'ext_csr_conf': '.toml', 
 'ext_policy': '.policy', 
 'ext_signedcert': '.zip.enc'}

>>> toml2config("intermediate") #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
{'private_keys': '#config#.private', 
 'passphrases': '#config#.private', 
 'csr_configs': '#config#csr', 
 'policies': '#config#/policies/intermediate', 
 'public_data': '#data#', 
 'certs': '#data#certs', 
 'chains': '#data#/chains', 
 'ext_cert': '.crt.pem', 
 'ext_public': '.pub.pem', 
 'ext_chain': '.chain.pem', 
 'ext_csr_conf': '.toml', 
 'ext_policy': '.policy', 
 'ext_signedcert': '.zip.enc'}

>>> toml2config("inter") #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
{'private_keys': '#config#.private', 
 'passphrases': '#config#.private', 
 'csr_configs': '#config#csr', 
 'policies': '#config#policies', 
 'public_data': '#data#', 
 'certs': '#data#certs', 
 'chains': '#data#/chains', 
 'ext_cert': '.crt.pem', 
 'ext_public': '.pub.pem', 
 'ext_chain': '.chain.pem', 
 'ext_csr_conf': '.toml', 
 'ext_policy': '.policy', 
 'ext_signedcert': '.zip.enc'}

>>> from ftwpki.baselibs.app_dirs import PKIDirs

>>> conf_file =PKIDirs().user_config_path / "pkiconfig.toml"


>>> conf_file.unlink()

>>> toml2config("inter") #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Traceback (most recent call last):
    ...
FileNotFoundError: [Errno 2] No such file or directory: '...pkiconfig.toml'


For Future Usage
-----------------

>>> from ftwpki.baselibs.toml_utils import toml2san_policy, toml2ext_policy

>>> toml2san_policy(pre_args.conf_file)
{'commonName': 'error'}

>>> toml2ext_policy(pre_args.conf_file)
{'commonName': 'error'}

>>> env.clean_home()
>>> env.teardown()
