Utilities for TOML
===================


>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)



>>> from ftwpki.baselibs.toml_utils import toml2dn

>>> from ftwpki.baselibs.cli_parser import ServerClientCSRParser

>>> pre_parser = ServerClientCSRParser(add_help=False)


>>> argv, _ = pre_parser.parse_known_args(["--conf-file", "not_there.toml"])


>>> conf_ca = env.copy2cwd("toml_2_dn_test.toml", "ca_conf.toml" )
>>> conf_ca.name
'ca_conf.toml'

>>> argv, _ = pre_parser.parse_known_args(["--conf-file", conf_ca.name, "test@example.org"])
>>> toml2dn(Path(argv.conf_file).read_text()) # doctest: +NORMALIZE_WHITESPACE
{'countryName': 'DE', 
 'organizationName': 'Fitzz TeXnik Welt', 
 'commonName': 'Fitzz Root CA', 
 'dnsubject': ''}

>>> conf_keyerror = env.copy2cwd("toml_2_dn_keyerror.toml", "ca_keyerror.toml" )
>>> argv, _ = pre_parser.parse_known_args(["--conf-file", conf_keyerror.name, "test@example.org"])
>>> toml2dn(Path(argv.conf_file).read_text())
Traceback (most recent call last):
    ...
ftwpki.baselibs.exceptions.PKIKeyError: No table 'identity.dn' in config file!


>>> conf_dec_error = env.copy2cwd("toml_decode_error.txt", "ca_decode_error.toml" )
>>> argv, _ = pre_parser.parse_known_args(["--conf-file", conf_dec_error.name, "test@example.org"])
>>> toml2dn(Path(argv.conf_file).read_text())
Traceback (most recent call last):
    ...
ftwpki.baselibs.exceptions.PKIConfigError: Could not decode file content!

tomllib.TOMLDecodeError: Could not decode file content!


>>> from ftwpki.baselibs.toml_utils import list_policy_sections

>>> data={"server":{"dn":""},"intermediate":{"dn"}, "clientsecure":{"dn"}, "client":{"san"}}
>>> list_policy_sections(data, "dn")
server
intermediate
clientsecure
True

>>> from ftwpki.baselibs.toml_utils import toml2dn_policy
>>> _ = env.copy2cwd("toml_2_dn_test.toml")
>>> argv,_ = pre_parser.parse_known_args(["--conf-file", "toml_2_dn_test.toml", "test@example.org"])

>>> toml2dn_policy(Path(argv.conf_file).read_text())
intermediate
server
user
server_l2
{'commonName': 'error'}

>>> from ftwpki.baselibs.cli_parser import PolicyParser

>>> pre_parser = PolicyParser(add_help=False)

>>> argv=["--conf-file", "toml_2_dn_test.toml", "--policy-name", "intermediate", "test@example.org"]
>>> pre_args , _ = pre_parser.parse_known_args(argv)

>> pre_args

>>> toml2dn_policy(Path(pre_args.conf_file).read_text(), pre_args.policy_name) # doctest: +ELLIPSIS   
{'countryName': 'match', 'organizationName': 'match', 'commonName': 'supplied'}

>>> toml2dn_policy(Path("toml_2_dn_test.toml").read_text(), "server") #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
{'countryName': 'match', 
 'organizationName': 'match', 
 'organizationalUnitName': 'supplied', 
 'commonName': 'supplied'}


>>> toml2dn_policy(None,'') # doctest: +ELLIPSIS   
Traceback (most recent call last):
    ...
TypeError: Expected str object, not 'NoneType'

AttributeError: 'NoneType' object has no attribute 'replace'

>>> toml2dn_policy(file_content=Path("toml_2_dn_test.toml").read_text()) # doctest: +ELLIPSIS   
intermediate
server
user
server_l2
{'commonName': 'error'}

>>> toml2dn_policy(file_content=Path("not_exists.toml").read_text()) # doctest: +ELLIPSIS   
Traceback (most recent call last):
    ...
FileNotFoundError: [Errno 2] No such file or directory: 'not_exists.toml'

>>> toml2dn_policy(Path("toml_2_dn_test.toml").read_text(), "secureintermediate") #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Traceback (most recent call last):
    ...
ftwpki.baselibs.exceptions.PKIKeyError: Key: secureintermediate.dn not found.

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


>>> from ftwpki.baselibs.toml_utils import _get_toml_policy_data
>>> _get_toml_policy_data("dn", "hallöli", "test")
Traceback (most recent call last):
    ...
ftwpki.baselibs.exceptions.PKIConfigError: Could not decode file content!

tomllib.TOMLDecodeError: Could not decode file content!


For Future Usage
-----------------

>>> from ftwpki.baselibs.toml_utils import toml2san_policy, toml2ext_policy

>>> toml2san_policy(pre_args.conf_file)
{'commonName': 'error'}

>>> toml2ext_policy(pre_args.conf_file)
{'commonName': 'error'}

>>> env.clean_home()
>>> env.teardown()
