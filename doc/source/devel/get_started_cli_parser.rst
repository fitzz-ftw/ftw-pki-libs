
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
    conf_file=None)

>>> from ftwpki.baselibs.cli_parser import CSRSigningParser

>>> csp=CSRSigningParser()

>>> csp  #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
CSRSigningParser(prog='...', 
    usage=None, 
    description=None, 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> csp.parse_args(["-C", "match"])  #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
Namespace(countryName='match', 
    stateOrProvinceName='no', 
    localityName='no', 
    organizationName='no', 
    organizationalUnitName='no', 
    commonName='no', 
    policy_name=None, 
    conf_file=None, 
    private_key=None, 
    private_dir=None)
