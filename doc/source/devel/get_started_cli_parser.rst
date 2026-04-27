Command Line Interface Parsers
================================


>>> from ftwpki.baselibs.cli_parser import DistinguishedNameParser

>>> dnp=DistinguishedNameParser()

>>> dnp #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
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


>>> from ftwpki.baselibs.cli_parser import CSRParser

>>> csr = CSRParser()
>>> csr #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
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
    private_key='', 
    public_key='', 
    privatdir='')


>>> from ftwpki.baselibs.cli_parser import PolicyParser

>>> pp = PolicyParser()
>>> pp #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
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
    policy_type='server',
    conf_file=None,
    policy={'countryName': 'match', 
        'stateOrProvinceName': 'no', 
        'localityName': 'no', 
        'organizationName': 'no', 
        'organizationalUnitName': 'no', 
        'commonName': 'no'})

>>> from ftwpki.baselibs.cli_parser import CSRSigningParser

>>> csp=CSRSigningParser()

>>> csp  #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
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
    policy_type='server', 
    conf_file=None, 
    private_key=None, 
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
        'commonName': 'no'})

>>> from ftwpki.baselibs.cli_parser import CertImportParser

>>> cip=CertImportParser(exit_on_error=False)
>>> cip #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
CertImportParser(prog='...', 
    usage=None, 
    description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> cip.parse_args([ "signed_certificat.zip.enc"])  #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Traceback (most recent call last):
    ...
argparse.ArgumentError: the following arguments are required: --keyfile/-k

SystemExit: 2

usage: cli_parser.py [-h] --keyfile PRIVATE_KEYFILE enc-zipfile
cli_parser.py: error: the following arguments are required: --keyfile/-k

>>> cip.parse_args([ "-k", "my-private-key",  "signed_certificat.zip.enc"])  #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Namespace(enc_zipfile='signed_certificat.zip.enc', 
    private_keyfile='my-private-key')

>>> from ftwpki.baselibs.cli_parser import IntermedImportParser

>>> iip= IntermedImportParser()
>>> iip #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
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
    private_keyfile='my-private-key', 
    policies='', 
    policy='server')
