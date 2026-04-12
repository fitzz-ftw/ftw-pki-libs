
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
