Command Line Interface Parsers
================================


>>> from ftwpki.baselibs.cli_parser import DistinguishedNameParser,get_dn_parser

>>> dnp=DistinguishedNameParser()

>>> dnp #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
DistinguishedNameParser(prog=..., 
    usage=None, 
    description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> get_dn_parser() #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
DistinguishedNameParser(prog=..., 
    usage=None, 
    description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> dnp.parse_args(["-C", "de" ]) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Namespace(countryName='de', 
    stateOrProvinceName='', 
    localityName='', 
    organizationName='', 
    organizationalUnitName='', 
    commonName='', 
    dnsubject={'countryName': 'de'}, 
    conf_file=None)

>>> dnp.parse_args(["-C", "de", "-subj", "/CN=Mein Name"  ]) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Namespace(countryName='de', 
    stateOrProvinceName='', 
    localityName='', 
    organizationName='', 
    organizationalUnitName='', 
    commonName='Mein Name', 
    dnsubject={'commonName': 'Mein Name', 
               'countryName': 'de'}, 
    conf_file=None)

>>> dnp.parse_args(["-C", "de", "-subj", "/CN:Mein Name"  ]) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Traceback (most recent call last):
    ...
argparse.ArgumentError: 
    argument -subj: 
        Ungültiges Subj-Format: 
    Fragment 'CN:Mein Name' does not contain '=' (Expected format: Key=Value)


>>> from ftwpki.baselibs.cli_parser import CSRParser, get_csr_parser

>>> csr = CSRParser()
>>> csr #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
 CSRParser(prog=..., 
    usage=None, description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> get_csr_parser() #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
 CSRParser(prog=..., 
    usage=None, description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> csr.parse_args(["-C", "de", "-subj", "/CN=Mein Name"  ]) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Namespace(countryName='de', 
    stateOrProvinceName='', 
    localityName='', 
    organizationName='', 
    organizationalUnitName='', 
    commonName='Mein Name', 
    dnsubject={'commonName': 'Mein Name', 
            'countryName': 'de'}, 
    conf_file=None, 
    key_name='', 
    privatdir='', 
    private_key='', 
    public_key='')

>>> from ftwpki.baselibs.cli_parser import ServerClientCSRParser, get_server_client_csr_parser

>>> sccsr = ServerClientCSRParser()
>>> sccsr #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
ServerClientCSRParser(prog=..., 
    usage=None, description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)  

>>> get_server_client_csr_parser() #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
ServerClientCSRParser(prog=..., 
    usage=None, description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> sccsr.parse_args(["-C", "de", "-subj", "/CN=Mein Name", "test@example.org"  ]) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Traceback (most recent call last):
    ...
argparse.ArgumentError: At least an ip address or a hostname has to be given

>>> sccsr.parse_args(["-C", "de","-ip", "192.168.1.1", "-subj", "/CN=Mein Name", "test@example.org"  ]) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Namespace(countryName='de', 
    stateOrProvinceName='', 
    localityName='', 
    organizationName='', 
    organizationalUnitName='', 
    commonName='Mein Name', 
    dnsubject={'commonName': 'Mein Name', 
            'countryName': 'de'}, 
    conf_file=None,  
    key_name='', 
    privatdir='',
    email='test@example.org',
    ip_addresses=['192.168.1.1'], 
    host_names=[], private_key='', public_key='')

>>> from ftwpki.baselibs.cli_parser import PolicyParser, get_policy_parser

>>> pp = PolicyParser()
>>> pp #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
PolicyParser(prog='...', 
    usage=None, 
    description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> get_policy_parser() #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
PolicyParser(prog='...', 
    usage=None, 
    description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> pp.parse_args(["-C", "match"]) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Namespace(countryName='match', 
    stateOrProvinceName='no', 
    localityName='no', 
    organizationName='no', 
    organizationalUnitName='no', 
    commonName='no', 
    policy_name=None,
    conf_file=None,
    policy={'countryName': 'match', 
        'stateOrProvinceName': 'no', 
        'localityName': 'no', 
        'organizationName': 'no', 
        'organizationalUnitName': 'no', 
        'commonName': 'no'})

>>> from ftwpki.baselibs.cli_parser import CSRSigningParser, get_csr_signing_parser

>>> csp=CSRSigningParser()

>>> csp  #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
CSRSigningParser(prog='...', 
    usage=None, 
    description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> get_csr_signing_parser() #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
CSRSigningParser(prog='...', 
    usage=None, 
    description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> csp.parse_args(["-C", "match", "passphrasefile", "certificat_sign_request"])  #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Namespace(countryName='match', 
    stateOrProvinceName='no', 
    localityName='no', 
    organizationName='no', 
    organizationalUnitName='no', 
    commonName='no', 
    policy_name=None,
    conf_file=None, 
    key_name=None, 
    private_dir=None,
    certificate='', 
    validity_days=365, 
    path_length=0, 
    passphrasefile='passphrasefile', 
    certificat_sign_request='certificat_sign_request', 
    policy={'countryName': 'match', 
        'stateOrProvinceName': 'no', 
        'localityName': 'no', 
        'organizationName': 'no', 
        'organizationalUnitName': 'no', 
        'commonName': 'no'},
    private_key='')

>>> from ftwpki.baselibs.cli_parser import CertImportParser, get_cert_import_parser

>>> cip=CertImportParser(exit_on_error=False)
>>> cip #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
CertImportParser(prog='...', 
    usage=None, 
    description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> get_cert_import_parser() #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
CertImportParser(prog='...', 
    usage=None, 
    description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> cip.parse_args([ "signed_certificat.zip.enc"])  #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Traceback (most recent call last):
    ...
argparse.ArgumentError: the following arguments are required: --key-name/-k

SystemExit: 2

usage: cli_parser.py [-h] --keyfile PRIVATE_KEYFILE enc-zipfile
cli_parser.py: error: the following arguments are required: --keyfile/-k

>>> cip.parse_args([ "-k", "my-private-key",  "signed_certificat.zip.enc"])  #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Namespace(enc_zipfile='signed_certificat.zip.enc',
    key_name='my-private-key',
    private_keyfile='my-private-key.key.pem')

>>> from ftwpki.baselibs.cli_parser import IntermedImportParser , get_intermed_import_parser

>>> iip= IntermedImportParser()
>>> iip #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
IntermedImportParser(prog='...', 
    usage=None, 
    description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> get_intermed_import_parser() #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
IntermedImportParser(prog='...', 
    usage=None, 
    description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> iip.parse_args([ "-k", "my-private-key", 
...     "-p", "server", 
...     "mypassphrasefile",
...     "signed_certificat.zip.enc"]
...     )  #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Namespace(passphrase_file='mypassphrasefile', 
    enc_zipfile='signed_certificat.zip.enc', 
    key_name='my-private-key', 
    policies='', 
    policy='server', 
    private_keyfile='my-private-key.key.pem')


>>> from ftwpki.baselibs.cli_parser import CSRMultiSigningParser, get_csr_multi_sign_parser
>>> multi_parser = CSRMultiSigningParser()
>>> multi_parser #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
CSRMultiSigningParser(prog='...', 
    usage=None, 
    description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> get_csr_multi_sign_parser() #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
CSRMultiSigningParser(prog='...', 
    usage=None, 
    description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> multi_parser.parse_args(["-C", "match", "passphrasefile", "certificat_sign_request"])  #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Namespace(countryName='match', 
    stateOrProvinceName='no', 
    localityName='no', 
    organizationName='no', 
    organizationalUnitName='no', 
    commonName='no', 
    policy_name=None,
    conf_file=None, 
    key_name=None, 
    private_dir=None,
    certificate='', 
    validity_days=365, 
    path_length=0, 
    passphrasefile='passphrasefile', 
    certificat_sign_request='certificat_sign_request', 
    policy_type='server',
    policy={'countryName': 'match', 
        'stateOrProvinceName': 'no', 
        'localityName': 'no', 
        'organizationName': 'no', 
        'organizationalUnitName': 'no', 
        'commonName': 'no'},
     private_key='')

