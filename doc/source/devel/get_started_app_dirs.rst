Application Directories
===========================


>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)

>>> from ftwpki.baselibs.app_dirs import _pki_dirs_instance

>>> _pki_dirs_instance  #doctest: +ELLIPSIS
<platformdirs.unix.Unix object at ...>



>>> from ftwpki.baselibs.app_dirs import PKIDirs
>>> PKIDirs()  #doctest: +ELLIPSIS
<platformdirs.unix.Unix object at ...>

>>> from ftwpki.baselibs.app_dirs import config_file_path
>>> config_file_path().as_posix()  #doctest: +ELLIPSIS
'.../.config/ftwpki/pkiconfig.toml'

>>> from ftwpki.baselibs.app_dirs import create_app_pathes
>>> testfiles={"private":"securedir", "public":"opendir", "testexist":"test"}
>>> Path("test").mkdir(exist_ok=True)
>>> create_app_pathes(testfiles,["private",], "private", "public", "testexist") #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
{'private': ...Path('...testoutput/securedir'), 
 'public': ...Path('...testoutput/opendir'), 
 'testexist': ...Path('...testoutput/test')}



>>> env.clean_home()
>>> env.teardown()
