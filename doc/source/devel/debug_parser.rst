:orphan:


>>> from ftwpki.baselibs._cli_parser import PKIBaseParser
>>> from ftwpki.baselibs._cli_parser import ServerClientCSRArguments
>>> from ftwpki.baselibs._cli_parser import parser_factory_creator
>>> from ftwpki.baselibs._cli_parser import server_client_parser
>>> import shlex
>>> cmd_line = " -k tim"
>>> cmd_line += " -dns www.secure.example.org"
>>> cmd_line += " www-admin@example.org"

>>> sys_argv= shlex.split(cmd_line) 


>>> tp1 = PKIBaseParser(arg_conf=ServerClientCSRArguments)

>>> tp1._conf.arguments #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
[(['-C', '--countryName']...(['--conf-file'], {'required': True,...

>>> tp1 #doctest: +ELLIPSIS
PKIBaseParser(...add_help=True)

>>> tp1.parse_args(sys_argv)
Traceback (most recent call last):
    ...
argparse.ArgumentError: the following arguments are required: --conf-file

>>> tp2 = PKIBaseParser(arg_conf=ServerClientCSRArguments, add_help= False)

>>> tp2._conf.arguments #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
[(['-C', '--countryName']...(['--conf-file'], {'required': False,...

>>> tp2.parse_args(sys_argv)
ServerClientCSRArguments(commonName=''
conf_file='None'
countryName=''
dnsubject={}
email='www-admin@example.org'
host_names=['www.secure.example.org']
ip_addresses=[]
key_name='tim'
localityName=''
organizationName=''
organizationalUnitName=''
password='None'
pki_name=''
privatdir=''
stateOrProvinceName='')

>>> tp2 #doctest: +ELLIPSIS
PKIBaseParser(...add_help=False)

>>> tp3 = PKIBaseParser(arg_conf=ServerClientCSRArguments, pre_parser=True)

>>> tp3.parse_args(sys_argv)
ServerClientCSRArguments(commonName=''
conf_file='None'
countryName=''
dnsubject={}
email='www-admin@example.org'
host_names=['www.secure.example.org']
ip_addresses=[]
key_name='tim'
localityName=''
organizationName=''
organizationalUnitName=''
password='None'
pki_name=''
privatdir=''
stateOrProvinceName='')


>>> tp3 #doctest: +ELLIPSIS
PKIBaseParser(...add_help=False)

>>> factory = parser_factory_creator(ServerClientCSRArguments)

>>> tf1 = factory()

kwargs={'arg_conf': <class 'ftwpki.baselibs._cli_parser.ServerClientCSRArguments'>}, pre_parser=False

>>> tf1.pre_parser
False

>>> tf1._conf.arguments #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
[(['-C', '--countryName']...(['--conf-file'], {'required': True,...



>> tf1.parse_args(sys_argv)
Traceback (most recent call last):
    ...
argparse.ArgumentError: the following arguments are required: --conf-file



>>> tf1 #doctest: +ELLIPSIS
PKIBaseParser(...add_help=True)

>>> tf2 = factory(pre_parser=True)

kwargs={'arg_conf': <class 'ftwpki.baselibs._cli_parser.ServerClientCSRArguments'>}, pre_parser=True

>>> tf2 #doctest: +ELLIPSIS
PKIBaseParser(...add_help=False)


>>> tsf1 = server_client_parser()

kwargs={'arg_conf': <class 'ftwpki.baselibs._cli_parser.ServerClientCSRArguments'>}, pre_parser=False

>>> tsf1 #doctest: +ELLIPSIS
PKIBaseParser(...add_help=True)

>>> tsf2 = server_client_parser(add_help=False)

kwargs={'add_help': False, 'arg_conf': <class 'ftwpki.baselibs._cli_parser.ServerClientCSRArguments'>}, pre_parser=False

>>> tsf2 #doctest: +ELLIPSIS
PKIBaseParser(...add_help=False)
