

>>> import sys

>>> from ftwpki.baselibs._cli_parser import CertImportArguments

>>> ciargs = CertImportArguments() #doctest:-SKIP

>>> ciargs #doctest:-SKIP
CertImportArguments(enc_zipfile=''
key_name='')


>>> ciargs.get_types() #doctest:-SKIP


>>> ciargs.setup_args() #doctest:-SKIP


>>> ciargs.arguments #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE -SKIP
[(['enc_zipfile'], 
  {'metavar': 'encrypted-zip-file', 
   'type': <class 'str'>, 
   'help': 'Path to the encrypted ZIP archive 
        containing the certificate(s).'}), 
 (['--key-name', '-k'], 
  {'default': 'password.txt', 
   'required': True, 
   'type': <class 'str'>, 
   'help': 'Identifier for the private key. 
        Used to resolve the corresponding key file (e.g., <name>.key.pem).', 
   'dest': 'key_name'})]

>>> ciargs.private_key
'.key.pem'

>>> ciargs.public_key
'.pub.pem'

>>> ci_pre =  CertImportArguments() #doctest: -SKIP

>>> ci_pre.get_types() #doctest:+SKIP

>>> ci_pre.setup_args(pre_parser=True) #doctest: -SKIP

>>> ci_pre.arguments #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE -SKIP
[(['enc_zipfile'], 
  {'metavar': 'encrypted-zip-file', 
   'type': <class 'str'>, 
   'help': 'Path to the encrypted ZIP archive containing 
            the certificate(s).', 
    'nargs': '?'}), 
  (['--key-name', '-k'], 
   {'default': 'password.txt', 
   'required': False, 
   'type': <class 'str'>, 
   'help': 'Identifier for the private key. Used to resolve the 
        corresponding key file (e.g., <name>.key.pem).', 
    'dest': 'key_name'})]


>>> from ftwpki.baselibs._cli_parser import IntermedImportArguments

>>> iiarg=IntermedImportArguments()

>>> iiarg
IntermedImportArguments(enc_zipfile=''
key_name=''
policies=''
policy='')

>>> iiarg.get_types()

>>> iiarg.setup_args()

>>> iiarg.arguments #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
[(['enc_zipfile'], 
  {'metavar': 'encrypted-zip-file', 
   'type': <class 'str'>, 
   'help': 'Path to the encrypted ZIP archive containing the 
        certificate(s).'}), 
 (['--key-name', '-k'], 
  {'default': 'password.txt', 
  'required': True, 'type': <class 'str'>, 
  'help': 'Identifier for the private key. Used to resolve the 
        corresponding key file (e.g., <name>.key.pem).', 
  'dest': 'key_name'}), 
 (['--policies-dir'], 
  {'default': '', 
   'type': <class 'str'>, 
   'help': 'Directory containing the policy configuration 
        files to be applied.', 
    'dest': 'policies'}), 
 (['-p', '--policy'], 
  {'required': True, 
   'type': <class 'str'>, 
   'help': 'The name of the policy to be used for this import operation.', 
   'dest': 'policy'})]

>>> from ftwpki.baselibs._cli_parser import PKIBaseParser
>>> tp = PKIBaseParser(arg_conf=IntermedImportArguments)
>>> tp #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
PKIBaseParser(prog='_cli_parser.py', 
    usage=None, 
    description='Encrypt a passphrase file into the out directory.', 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> tp.print_help() #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
usage: ... [-h] --key-name KEY_NAME [--policies-dir POLICIES] -p POLICY
                        encrypted-zip-file
<BLANKLINE>
Encrypt a passphrase file into the out directory.
<BLANKLINE>
positional arguments:
    encrypted-zip-file    Path to the encrypted ZIP archive containing the certificate(s).
<BLANKLINE>
options:
    -h, --help            show this help message and exit
    --key-name KEY_NAME, -k KEY_NAME
                        Identifier for the private key. Used to resolve the corresponding
                        key file (e.g., <name>.key.pem).
    --policies-dir POLICIES
                        Directory containing the policy configuration files to be applied.
    -p POLICY, --policy POLICY
                        The name of the policy to be used for this import operation.

>>> sys_argv=["-k", "testkey","-p","server", "testfile.spki"]

>>> tp.parse_args(sys_argv)
IntermedImportArguments(enc_zipfile='testfile.spki'
key_name='testkey'
policies=''
policy='server')

>>> from ftwpki.baselibs._cli_parser import DistinguishedNameArguments

>>> dnarg = DistinguishedNameArguments()

>>> dnarg.get_types()

>>> dnarg.setup_args()

>>> dnarg.arguments #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
[(['-C', '--countryName'], 
  {'default': '', 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'ISO 3166-1 alpha-2 country code (e.g., DE, US). Affects certificate trust and 
            legal jurisdiction. (Default: %(default)s)', 
   'dest': 'countryName'}), 
 (['-ST', '--stateOrProvinceName'], 
  {'default': '', 
   'sub_parser': 'dn',
  'type': <class 'str'>, 
  'help': 'Full name of the state or province. Important for identifying the physical 
            location of the entity. (Default: %(default)s)', 
  'dest': 'stateOrProvinceName'}), 
 (['-L', '--localityName'], 
  {'default': '', 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'City or town name. Essential for physical identity verification in 
            high-assurance certificates. (Default: %(default)s)', 
   'dest': 'localityName'}), 
 (['-O', '--organizationName'], 
  {'default': '', 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'Legal name of the organization. Often used in OV (Organization Validated) 
            certificates to prove legal entity existence. (Default: %(default)s)', 
   'dest': 'organizationName'}), 
 (['-OU', '--organizationalUnitName'], 
  {'default': '', 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'Department or section name (e.g., IT, Security). Used to distinguish internal 
            responsibilities within the organization. (Default: %(default)s)', 
   'dest': 'organizationalUnitName'}), 
 (['-CN', '--commonName'], 
  {'default': '', 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'The primary identifier (FQDN or name) the certificate is issued to. Crucial 
            for TLS handshake validation. (Default: %(default)s)', 
   'dest': 'commonName'}), 
 (['-subj'], 
  {'default': '', 
   'action': <class 'ftwpki.baselibs._cli_parser.SubjAction'>, 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'Full Distinguished Name string. Overrides individual flags. 
            Use format: /C=DE/O=Company/CN=example.com. (Default: %(default)s)', 
   'dest': 'dnsubject'})]

>>> from ftwpki.baselibs._cli_parser import CSRArguments

>>> csr_args = CSRArguments()

>>> csr_args
CSRArguments(commonName=''
conf_file='.'
countryName=''
dnsubject={}
key_name=''
localityName=''
organizationName=''
organizationalUnitName=''
pki_name=''
privatdir=''
stateOrProvinceName='')

>>> csr_args.get_types()

>>> csr_args.setup_args()

>>> csr_args.arguments #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
[(['-C', '--countryName'], 
  {'default': '', 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'ISO 3166-1 alpha-2 country code (e.g., DE, US). Affects certificate trust and 
            legal jurisdiction. (Default: %(default)s)', 
   'dest': 'countryName'}), 
 (['-ST', '--stateOrProvinceName'], 
  {'default': '', 
   'sub_parser': 'dn',
  'type': <class 'str'>, 
  'help': 'Full name of the state or province. Important for identifying the physical 
            location of the entity. (Default: %(default)s)', 
  'dest': 'stateOrProvinceName'}), 
 (['-L', '--localityName'], 
  {'default': '', 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'City or town name. Essential for physical identity verification in 
            high-assurance certificates. (Default: %(default)s)', 
   'dest': 'localityName'}), 
 (['-O', '--organizationName'], 
  {'default': '', 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'Legal name of the organization. Often used in OV (Organization Validated) 
            certificates to prove legal entity existence. (Default: %(default)s)', 
   'dest': 'organizationName'}), 
 (['-OU', '--organizationalUnitName'], 
  {'default': '', 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'Department or section name (e.g., IT, Security). Used to distinguish internal 
            responsibilities within the organization. (Default: %(default)s)', 
   'dest': 'organizationalUnitName'}), 
 (['-CN', '--commonName'], 
  {'default': '', 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'The primary identifier (FQDN or name) the certificate is issued to. Crucial 
            for TLS handshake validation. (Default: %(default)s)', 
   'dest': 'commonName'}), 
 (['-subj'], 
  {'default': '', 
   'action': <class 'ftwpki.baselibs._cli_parser.SubjAction'>, 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'Full Distinguished Name string. Overrides individual flags. 
            Use format: /C=DE/O=Company/CN=example.com. (Default: %(default)s)', 
   'dest': 'dnsubject'}),
 (['--conf-file'], 
  {'required': True, 
   'type': <class 'pathlib.PosixPath'>, 
   'help': 'Path to a TOML-Configfile. This file defines the core parameters for the CSR generation.', 
   'dest': 'conf_file'}), 
 (['-k', '--key', '--key-name'], 
  {'default': '', 
   'required': True, 
   'type': <class 'str'>, 
   'help': 'Key identifier used to reference the private key. Must correspond to the internal key storage name.', 
   'dest': 'key_name'}), 
 (['-n', '--name'], 
  {'default': '', 
   'type': <class 'str'>, 
   'help': 'Name for the Configuration. Used to group settings in the PKI management system.', 
   'dest': 'pki_name'}), 
 (['--private-dir'], 
  {'default': '', 
   'type': <class 'str'>, 
   'help': 'Directory where the private keys are stored securely. Defaults to the base security folder.', 
   'dest': 'privatdir'})]

>>> from ftwpki.baselibs._cli_parser import ServerClientCSRArguments

>>> cs_csr_args = ServerClientCSRArguments()

>>> cs_csr_args
ServerClientCSRArguments(commonName=''
conf_file='.'
countryName=''
dnsubject={}
host_names=[]
ip_addresses=[]
key_name=''
localityName=''
organizationName=''
organizationalUnitName=''
password=''
pki_name=''
privatdir=''
stateOrProvinceName='')

>>> cs_csr_args.get_types()

>>> cs_csr_args.setup_args()

>>> cs_csr_args.arguments #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE +REPORT_NDIFF
[(['-C', '--countryName'], 
  {'default': '', 
   'sub_parser': 'dn', 
   'type': <class 'str'>, 
   'help': 'ISO 3166-1 alpha-2 country code (e.g., DE, US). Affects certificate trust and legal jurisdiction. (Default: %(default)s)', 
   'dest': 'countryName'}), 
 (['-ST', '--stateOrProvinceName'], 
  {'default': '', 
   'sub_parser': 'dn', 
   'type': <class 'str'>, 
   'help': 'Full name of the state or province. Important for identifying the physical location of the entity. (Default: %(default)s)', 
   'dest': 'stateOrProvinceName'}), 
 (['-L', '--localityName'], 
  {'default': '', 
   'sub_parser': 'dn', 
   'type': <class 'str'>, 
   'help': 'City or town name. Essential for physical identity verification in high-assurance certificates. (Default: %(default)s)', 
   'dest': 'localityName'}), 
 (['-O', '--organizationName'], 
  {'default': '', 
   'sub_parser': 'dn', 
   'type': <class 'str'>, 
   'help': 'Legal name of the organization. Often used in OV (Organization Validated) certificates to prove legal entity existence. (Default: %(default)s)', 
   'dest': 'organizationName'}), 
 (['-OU', '--organizationalUnitName'], 
  {'default': '', 
   'sub_parser': 'dn', 
   'type': <class 'str'>, 
   'help': 'Department or section name (e.g., IT, Security). Used to distinguish internal responsibilities within the organization. (Default: %(default)s)', 
   'dest': 'organizationalUnitName'}), 
 (['-CN', '--commonName'], 
  {'default': '', 
   'sub_parser': 'dn', 
   'type': <class 'str'>, 
   'help': 'The primary identifier (FQDN or name) the certificate is issued to. Crucial for TLS handshake validation. (Default: %(default)s)', 
   'dest': 'commonName'}), 
 (['-subj'], 
  {'default': '', 
   'action': <class 'ftwpki.baselibs._cli_parser.SubjAction'>, 
   'sub_parser': 'dn', 
   'type': <class 'str'>, 
   'help': 'Full Distinguished Name string. Overrides individual flags. Use format: /C=DE/O=Company/CN=example.com. (Default: %(default)s)', 
   'dest': 'dnsubject'}), 
 (['--conf-file'], 
  {'required': True, 
   'type': <class 'pathlib.PosixPath'>, 
   'help': 'Path to a TOML-Configfile. This file defines the core parameters for the CSR generation.', 
   'dest': 'conf_file'}), 
 (['-k', '--key', '--key-name'], 
  {'default': '', 
   'required': True, 
   'type': <class 'str'>, 
   'help': 'Key identifier used to reference the private key. Must correspond to the internal key storage name.', 
   'dest': 'key_name'}), 
 (['-n', '--name'], 
  {'default': '', 
   'type': <class 'str'>, 
   'help': 'Name for the Configuration. Used to group settings in the PKI management system.', 
   'dest': 'pki_name'}), 
 (['--private-dir'], 
  {'default': '', 
   'type': <class 'str'>, 
   'help': 'Directory where the private keys are stored securely. Defaults to the base security folder.', 
   'dest': 'privatdir'}), 
 (['-ip', '--ip-address'], 
  {'action': 'append', 
   'default': [], 
   'sub_parser': 'san', 
   'type': <class 'list'>, 
   'help': 'IP address(es) to include in the certificate. Can be specified multiple times.', 
   'dest': 'ip_addresses'}), 
 (['-dns', '--host-name'], 
  {'action': 'append', 
   'default': [], 
   'sub_parser': 'dn', 
   'type': <class 'list'>, 
   'help': 'Hostname(s) or FQDN(s) associated with the certificate. Can be specified multiple times.', 
   'dest': 'host_names'}), 
 (['--password'], 
  {'type': <class 'str'>, 
   'help': 'Password for protecting the private key. Note: Avoid using this for server-side automated deployments.', 
   'dest': 'password'})]


[(['-C', '--countryName'], 
  {'default': '', 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'ISO 3166-1 alpha-2 country code (e.g., DE, US). Affects certificate trust and 
            legal jurisdiction. (Default: %(default)s)', 
   'dest': 'countryName'}), 
 (['-ST', '--stateOrProvinceName'], 
  {'default': '', 
   'sub_parser': 'dn',
  'type': <class 'str'>, 
  'help': 'Full name of the state or province. Important for identifying the physical 
            location of the entity. (Default: %(default)s)', 
  'dest': 'stateOrProvinceName'}), 
 (['-L', '--localityName'], 
  {'default': '', 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'City or town name. Essential for physical identity verification in 
            high-assurance certificates. (Default: %(default)s)', 
   'dest': 'localityName'}), 
 (['-O', '--organizationName'], 
  {'default': '', 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'Legal name of the organization. Often used in OV (Organization Validated) 
            certificates to prove legal entity existence. (Default: %(default)s)', 
   'dest': 'organizationName'}), 
 (['-OU', '--organizationalUnitName'], 
  {'default': '', 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'Department or section name (e.g., IT, Security). Used to distinguish internal 
            responsibilities within the organization. (Default: %(default)s)', 
   'dest': 'organizationalUnitName'}), 
 (['-CN', '--commonName'], 
  {'default': '', 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'The primary identifier (FQDN or name) the certificate is issued to. Crucial 
            for TLS handshake validation. (Default: %(default)s)', 
   'dest': 'commonName'}), 
 (['-subj'], 
  {'default': '', 
   'action': <class 'ftwpki.baselibs._cli_parser.SubjAction'>, 
   'sub_parser': 'dn',
   'type': <class 'str'>, 
   'help': 'Full Distinguished Name string. Overrides individual flags. 
            Use format: /C=DE/O=Company/CN=example.com. (Default: %(default)s)', 
   'dest': 'dnsubject'}),
 (['--conf-file'], 
  {'required': True, 
   'type': <class 'pathlib.PosixPath'>, 
   'help': 'Path to a TOML-Configfile. This file defines the core parameters for the CSR generation.', 
   'dest': 'conf_file'}), 
 (['-k', '--key', '--key-name'], 
  {'default': '', 
   'required': True, 
   'type': <class 'str'>, 
   'help': 'Key identifier used to reference the private key. Must correspond to the internal key storage name.', 
   'dest': 'key_name'}), 
 (['-n', '--name'], 
  {'default': '', 
   'type': <class 'str'>, 
   'help': 'Name for the Configuration. Used to group settings in the PKI management system.', 
   'dest': 'pki_name'}), 
 (['--private-dir'], 
  {'default': '', 
   'type': <class 'str'>, 
   'help': 'Directory where the private keys are stored securely. Defaults to the base security folder.', 
   'dest': 'privatdir'}),
 (['-ip', '--ip-address'], 
  {'action': 'append', 
   'default': [],
   'sub_parser': 'san',
   'type': <class 'list'>, 
   'help': 'IP address(es) to include in the certificate. Can be specified multiple times.', 
   'dest': 'ip_addresses'}), 
 (['-dns', '--host-name'], 
  {'action': 'append', 
   'default': [],
   'sub_parser': 'san',
   'type': <class 'list'>, 
   'help': 'Hostname(s) or FQDN(s) associated with the certificate. Can be specified multiple times.', 
   'dest': 'host_names'}), 
 (['--password'], 
  {'type': <class 'str'>, 
   'help': 'Password for protecting the private key. Note: Avoid using this for server-side 
            automated deployments.', 
   'dest': 'password'})]

>>> from ftwpki.baselibs._cli_parser import PolicyArguments

>>> pol_args = PolicyArguments()

>>> pol_args
PolicyArguments(commonName='no'
conf_file='.'
countryName='no'
localityName='no'
organizationName='no'
organizationalUnitName='no'
policy_name=''
stateOrProvinceName='no')

>>> pol_args.get_types()

>>> pol_args.setup_args()

>>> pol_args.arguments #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
[(['-C', '--countryName'], 
  {'choices': ['match', 'optional', 'supplied', 'no'], 
   'default': 'no', 
   'type': <class 'str'>, 
   'help': 'Policy for Country Name. Specifies whether the field must match, is optional, supplied, or not allowed.', 
   'dest': 'countryName'}), 
 (['-ST', '--stateOrProvinceName'], 
  {'choices': ['match', 'optional', 'supplied', 'no'], 
   'default': 'no', 
   'type': <class 'str'>, 
   'help': 'Policy for State or Province Name. Specifies whether the field must match, is optional, supplied, or not allowed.', 
   'dest': 'stateOrProvinceName'}), 
 (['-L', '--localityName'], 
  {'choices': ['match', 'optional', 'supplied', 'no'], 
   'default': 'no', 
   'type': <class 'str'>, 
   'help': 'Policy for Locality Name. Specifies whether the field must match, is optional, supplied, or not allowed.', 
   'dest': 'localityName'}), 
 (['-O', '--organizationName'], 
  {'choices': ['match', 'optional', 'supplied', 'no'], 
   'default': 'no', 
   'type': <class 'str'>, 
   'help': 'Policy for Organization Name. Specifies whether the field must match, is optional, supplied, or not allowed.', 
   'dest': 'organizationName'}), 
 (['-OU', '--organizationalUnitName'], 
  {'choices': ['match', 'optional', 'supplied', 'no'], 
   'default': 'no', 
   'type': <class 'str'>, 
   'help': 'Policy for Organizational Unit Name. Specifies whether the field must match, is optional, supplied, or not allowed.', 
   'dest': 'organizationalUnitName'}), 
 (['-CN', '--commonName'], 
  {'choices': ['match', 'optional', 'supplied', 'no'], 
   'default': 'no', 
   'type': <class 'str'>, 
   'help': 'Policy for Common Name. Specifies whether the field must match, is optional, supplied, or not allowed.', 
   'dest': 'commonName'}), 
 (['-p', '--policy-name'], 
  {'default': None, 
  'type': <class 'str'>, 
  'help': 'Name of the policy configuration. Used to uniquely identify this policy rule set.', 
  'dest': 'policy_name'}), 
 (['--conf-file'], 
  {'type': <class 'pathlib.PosixPath'>, 
   'help': 'Path to a TOML-Configfile defining the certificate issuance constraints.', 
   'dest': 'conf_file'})]


>>> tp1 = PKIBaseParser(arg_conf=ServerClientCSRArguments())

>>> tp1.print_help(file=sys.stderr)
