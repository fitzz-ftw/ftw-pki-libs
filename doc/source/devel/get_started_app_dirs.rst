Application Directories
===========================


>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)

>>> from ftwpki.baselibs.app_dirs import _pki_dirs_instance

>>> from platformdirs import PlatformDirs

>>> isinstance(_pki_dirs_instance, PlatformDirs)
True



>>> from ftwpki.baselibs.app_dirs import PKIDirs
>>> isinstance(PKIDirs(), PlatformDirs)
True

>>> from ftwpki.baselibs.app_dirs import config_file_path
>>> config_file_path().as_posix()  #doctest: +ELLIPSIS
'.../ftwpki/pkiconfig.toml'

>>> from ftwpki.baselibs.app_dirs import create_app_pathes
>>> testfiles={"private":"securedir", "public":"opendir", "testexist":"test"}
>>> Path("test").mkdir(exist_ok=True)
>>> create_app_pathes(testfiles,["private",], "private", "public", "testexist") #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
{'private': ...Path('...testoutput/securedir'), 
 'public': ...Path('...testoutput/opendir'), 
 'testexist': ...Path('...testoutput/test')}


>>> from ftwpki.baselibs.app_dirs import get_uni_path


>>> get_uni_path("~.config/test").as_posix() #doctest: +ELLIPSIS
'~.config/test'

>>> get_uni_path("#config#test").as_posix() #doctest: +ELLIPSIS
'.../ftwpki/test'

'testhome/.config/ftwpki/test'


>>> get_uni_path("#data#test1/test2").as_posix() #doctest: +ELLIPSIS
'.../ftwpki/test1/test2'

'testhome/.local/share/ftwpki/test1/test2'

>>> get_uni_path("#undefined#test1/test2").as_posix() #doctest: +ELLIPSIS
'#undefined#test1/test2'


>>> env.clean_home()
>>> env.teardown()
