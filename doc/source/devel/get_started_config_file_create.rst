

>>> from fitzzftw.develtool.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)



>>> from ftwpki.baselibs.config_file_create import toml_conf_str, write_example_config

>>> write_example_config(toml_conf_str)
>>> write_example_config(toml_conf_str)
>>> from ftwpki.baselibs.app_dirs import PKIDirs
>>> conf_file = PKIDirs().user_config_path / "config.toml"
>>> conf_file.unlink()
>>> write_example_config(toml_conf_str)


>>> env.teardown()
