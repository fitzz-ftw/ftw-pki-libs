# File: src/ftwpki/baselibs/configuration.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
configuration
===============================


Modul configuration documentation
"""

from pathlib import Path

from ftwpki.baselibs.app_dirs import config_file_path, create_app_pathes
from ftwpki.baselibs.config_file_create import (
    INTERMED_CONFIG,
    LEAF_CONFIG,
    ROOT_SIGNER_CONFIG,
    USER_CONFIG,
    toml_conf_str,
    write_example_config,
)
from ftwpki.baselibs.toml_utils import toml2config


# CLASS - BasePKIConfig
class BasePKIConfig:
    # DOC - Hier könnte eine ausführliche Beschreibung der Klasse stehen, z.B.:
    def __init__(self, file_name: str | None = None) -> None:
        """Initialisiert die Konfiguration direkt aus der Datei."""
        self._path: Path = config_file_path(file_name=file_name)
        if not self._path.is_file():
            match file_name:
                case "user.toml":
                    conf_str = USER_CONFIG
                case "leaf.toml":
                    conf_str = LEAF_CONFIG
                case "intermed.toml":
                    conf_str = INTERMED_CONFIG
                case "rsign.toml":
                    conf_str = ROOT_SIGNER_CONFIG
                case _:
                    conf_str = toml_conf_str
            write_example_config(conf_str)

        self._secure_dirs: list[str] = ["private_keys"]
        self._raw_data: dict[str,str] = {}

        # create_app_pathes erledigt die Validierung/Erstellung
        # und gibt ein dict mit Path-Objekten zurück
        self._paths: dict[str, Path]= {}

    # DOC - Hier könnten weitere Methoden und Eigenschaften der Klasse beschrieben werden, z.B.:
    def set_config(self, section: str = "") -> None:
        self._raw_data: dict[str,str] = toml2config(section=section)
        # Wir filtern alles aus, was kein Pfad ist (deine 'ext'-Logik)
        dirs_to_setup: list[str] = [k for k in self._raw_data if not k.startswith("ext")]
        # create_app_pathes erledigt die Validierung/Erstellung
        # und gibt ein dict mit Path-Objekten zurück
        self._paths: dict[str, Path] = create_app_pathes(
            self._raw_data, self._secure_dirs, *dirs_to_setup
        )

    # DOC - Docstring
    @property
    def private_keys(self) -> str:
        return self._raw_data["private_keys"]

    # DOC - Docstring
    @property
    def public_data(self) -> str:
        return self._raw_data["public_data"]

    # DOC - Docstring
    @property
    def certs(self) -> str:
        return self._raw_data["certs"]

    # DOC - Docstring
    @property
    def chains(self) -> str:
        return self._raw_data["chains"]

    # DOC - Docstring
    @property
    def ext_cert(self) -> str:
        return self._raw_data["ext_cert"]

    # DOC - Docstring
    @property
    def ext_public(self) -> str:
        return self._raw_data["ext_public"]

    # DOC - Docstring
    @property
    def ext_signedcert(self) -> str:
        return self._raw_data["ext_signedcert"]


    # DOC - Docstring
    def resolve(self, name: str, category: str) -> Path:
        """
        Der intelligente Pfad-Resolver für Leaf-Programme.
        category entspricht dem Key in der Config (z.B. 'private_keys').
        """
        if name.startswith(("./", ".\\")):
            return Path(name).resolve()

        p = Path(name)
        if p.is_absolute():
            return p

        base = self._paths.get(category)
        if base is None:
            raise KeyError(f"Pfad-Kategorie '{category}' nicht konfiguriert.")

        return base / p

    # DOC - Docstring
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(Path={self._path.as_posix()})"

# !CLASS - BasePKIConfig


# CLASS - UserPKIConfig
# DOC - Docstring
class UserPKIConfig(BasePKIConfig):
    # DOC - Docstring
    def __init__(self, file_name: str | None = "user.toml") -> None:
        super().__init__(file_name)
        self.set_config()


# !CLASS - UserPKIConfig

# CLASS - Leaf Configuration
# DOC - Docstring
class LeafPKIConfig(BasePKIConfig):
    # DOC - Docstring
    def __init__(self, file_name: str | None = "leaf.toml") -> None:
        super().__init__(file_name)
        self.set_config()

# !CLASS - Leaf Configuration

# CLASS - Root Signer Configuration
# DOC - Docstring
class RootSignerPKIConfig(BasePKIConfig):
    # DOC - Docstring
    def __init__(self, file_name: str | None = "rsign.toml") -> None:
        super().__init__(file_name)
        self._secure_dirs.append("passphrases")
        self.set_config()

    # DOC - Docstring
    @property
    def passphrases(self) -> str:
        return self._raw_data["passphrases"]

    # DOC - Docstring
    @property
    def ext_chain(self) -> str:
        return self._raw_data["ext_chain"]


# !CLASS - Root Signer Configuration

# CLASS - Intermediate Configuration
# DOC - Docstring
class IntermedPKIConfig(RootSignerPKIConfig):
    # DOC - Docstring
    def __init__(self, file_name: str | None = "intermed.toml") -> None:
        super().__init__(file_name)

    # DOC - Docstring
    @property
    def policies(self) -> str:
        return self._raw_data["policies"]

    # DOC - Docstring
    @property
    def ext_policy(self) -> str:
        return self._raw_data["ext_policy"]


# !CLASS - Intermediate Configuration


if __name__ == "__main__":  # pragma: no cover
    from doctest import FAIL_FAST, testfile

    be_verbose = False
    be_verbose = True
    option_flags = 0
    option_flags = FAIL_FAST
    test_sum = 0
    test_failed = 0
    passed_files = 0
    # Pfad zu den dokumentierenden Tests
    testfiles_dir = Path(__file__).parents[3] / "doc/source/devel"
    test_files = [
        "configuration.rst",
    ]
    for file in test_files:
        test_file = testfiles_dir / file
        if test_file.exists():
            print(f"--- Running Doctest for {test_file.name} ---")
            doctestresult = testfile(
                str(test_file),
                module_relative=False,
                verbose=be_verbose,
                optionflags=option_flags,
            )
            test_failed += doctestresult.failed
            test_sum += doctestresult.attempted
            if doctestresult.failed > 0 and option_flags & FAIL_FAST:
                print(f"Doctest result for {test_file.name}: {doctestresult}")
                print(
                    f"\nKeep going! You already passed {passed_files} files "
                    f"with {test_sum} tests before this hit."
                )
                break  # Stop on first failure if FAIL_FAST is set
            passed_files += 1
        else:
            print(f"⚠️ Warning: Test file {test_file.name} not found.")
    if test_failed == 0:
        print(f"\nDocTests passed without errors, {test_sum} tests.")
    else:
        if not option_flags & FAIL_FAST:
            print(f"\nDocTests failed: {test_failed} tests out of {test_sum}.")
