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
from types import SimpleNamespace
from typing import Any, NamedTuple, cast

from ftwpki.baselibs.app_dirs import config_file_path, create_app_pathes
from ftwpki.baselibs.config_file_create import (
    INTERMED_CONFIG,
    LEAF_CONFIG,
    ROOT_SIGNER_CONFIG,
    USER_CONFIG,
    toml_conf_str,
    write_example_config,
)
from ftwpki.baselibs.protocols import (
    IntermedPathConfigPathesProtocol,
    LeafPathConfigPathesProtocol,
    PathCategoryType,
    PathConfigPathesProtocol,
    RootSignPathConfigPathesProtocol,
    UserPathConfigPathesProtocol,
)
from ftwpki.baselibs.toml_utils import toml2config


# CLASS - BasePKIConfig
class BasePKIConfig:
    """
    Base class for managing PKI configurations.

    This class handles the automatic creation of configuration files and
    provides methods to resolve relative paths into absolute ones based
    on the configuration directory.
    """
    def __init__(self, file_name: str | None = None) -> None:
        """
        Initialize the configuration directly from a file.

        :param file_name: Name of the configuration file.
        :raises PermissionError: If there are insufficient rights to create
                                 the configuration or directories.
        """
        self._path: Path = config_file_path(file_name=file_name)
        conf_str="Blödsinn"
        if not self._path.is_file():
            match file_name:
                case "user.toml":
                    # print(f"{file_name=}")
                    conf_str = USER_CONFIG
                case "leaf.toml":
                    conf_str = LEAF_CONFIG
                case "intermed.toml":
                    conf_str = INTERMED_CONFIG
                case "rsign.toml":
                    conf_str = ROOT_SIGNER_CONFIG
                case _:
                    print(f"{file_name=}")
                    conf_str = toml_conf_str
                    # print(conf_str)
            write_example_config(conf_str,file_name=file_name)

        self._secure_dirs: list[str] = ["private_keys"]
        self._raw_data: dict[str, str] = {}

        # create_app_pathes erledigt die Validierung/Erstellung
        # und gibt ein dict mit Path-Objekten zurück
        self._paths: dict[str, Path] = {}

    def set_config(self, section: str = "") -> None:
        """
        Load and setup the configuration paths from a specific section.

        :param section: The section name within the TOML file.
        """
        self._raw_data: dict[str, str] = toml2config(section=section)
        dirs_to_setup: list[str] = [k for k in self._raw_data if not k.startswith("ext")]
        self._paths: dict[str, Path] = create_app_pathes(
            self._raw_data, self._secure_dirs, *dirs_to_setup
        )

    @property
    def private_keys(self) -> str:
        """
        The path to the private keys directory **(ro)**.

        :returns: The directory path as defined in the configuration.
        """
        return self._raw_data["private_keys"]

    @property
    def public_data(self) -> str:
        """
        The path to the public data directory **(ro)**.

        :returns: The directory path for public files.
        """
        return self._raw_data["public_data"]

    @property
    def certs(self) -> str:
        """
        The path to the directory where certificates are stored **(ro)**.

        :returns: The directory path for certificates.
        """
        return self._raw_data["certs"]

    @property
    def chains(self) -> str:
        """
        The path to the directory where certificate chains are stored **(ro)**.

        :returns: The directory path for chains.
        """
        return self._raw_data["chains"]

    @property
    def ext_cert(self) -> str:
        """
        The file extension for certificate files **(ro)**.

        :returns: The configured certificate extension.
        """
        return self._raw_data["ext_cert"]

    @property
    def ext_public(self) -> str:
        """
        The file extension for public data files **(ro)**.

        :returns: The configured public data extension.
        """
        return self._raw_data["ext_public"]

    @property
    def ext_signedcert(self) -> str:
        """
        The file extension for signed certificates **(ro)**.

        :returns: The configured signed certificate extension.
        """
        return self._raw_data["ext_signedcert"]

    def resolve(self, name: str, category: PathCategoryType|None=None) -> Path:
        """
        Resolve a string name into an absolute Path object.

        This method converts relative names into absolute paths using
        the specified category or the current user home.

        :param name: The name or relative path of the file.
        :param category: The configuration category for path lookup.
        :raises KeyError: If the provided category is not found in
                          the configuration.
        :returns: The resolved absolute Path object.
        """
        if name.startswith(("./", ".\\")):
            return Path(name).resolve()

        p = Path(name)
        if p.is_absolute():
            return p
        if category:
            base = self._paths.get(category)
            if base is None:
                raise KeyError(f"Pfad-Kategorie '{category}' nicht konfiguriert.")

            return base / p
        else:
            return Path(name).expanduser().resolve()

    def as_path(self,read_only:bool=True) ->PathConfigPathesProtocol:
        """
        Return the configuration paths as a structured object.

        :param read_only: If True, returns a NamedTuple (ro), 
                          otherwise a SimpleNamespace (rw).
        :returns: An object providing access to all directory Path objects.
        """
        if read_only:
            fields = [(k, Path) for k in self._paths]
            PathContainerRO = NamedTuple("PathContainerRO", fields)
            # PathContainerRO = NamedTuple("PathContainerRO", **{k: Path for k in self._paths})
            return cast(PathConfigPathesProtocol,PathContainerRO(**self._paths))
        else:
            class PathContainerRW(SimpleNamespace):
                def __iter__(self)->Any:
                    return iter(self.__dict__.values())
            return cast(PathConfigPathesProtocol,PathContainerRW(**self._paths))


    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(Path={self._path.as_posix()})"


# !CLASS - BasePKIConfig


# CLASS - UserPKIConfig
class UserPKIConfig(BasePKIConfig):
    """
    Configuration class for user-specific PKI settings.

    This class inherits from BasePKIConfig and specializes it for
    handling the user configuration file.
    """
    def __init__(self, file_name: str | None = "user.toml") -> None:
        """
        Initialize the User PKI configuration.

        :param file_name: Name of the configuration file.
        """
        super().__init__(file_name)
        self.set_config()

    def as_path(self, read_only: bool = True) -> UserPathConfigPathesProtocol:
        """
        Return the configuration paths as a structured object.

        :param read_only: If True, returns a NamedTuple (ro), 
                          otherwise a SimpleNamespace (rw).
        :returns: An object providing access to all directory Path objects.
        """
        return cast(UserPathConfigPathesProtocol,super().as_path(read_only))


# !CLASS - UserPKIConfig


# CLASS - Leaf Configuration
class LeafPKIConfig(BasePKIConfig):
    """
    Configuration class for leaf applications.

    This class provides settings for clients, servers, and client-server
    applications that interact within the PKI infrastructure.
    """
    def __init__(self, file_name: str | None = "leaf.toml") -> None:
        """
        Initialize the Leaf PKI configuration.

        :param file_name: Name of the configuration file.
        """
        super().__init__(file_name)
        self.set_config()

    def as_path(self, read_only: bool = True) -> LeafPathConfigPathesProtocol:
        """
        Return the configuration paths as a structured object.

        :param read_only: If True, returns a NamedTuple (ro), 
                          otherwise a SimpleNamespace (rw).
        :returns: An object providing access to all directory Path objects.
        """
        return cast(LeafPathConfigPathesProtocol,super().as_path(read_only))


# !CLASS - Leaf Configuration


# CLASS - Root Signer Configuration
class RootSignerPKIConfig(BasePKIConfig):
    """
    Configuration class for Root Signer applications.

    This class handles settings for Root CAs and signing entities,
    including secure storage for passphrases and chain extensions.
    """
    def __init__(self, file_name: str | None = "rsign.toml") -> None:
        """
        Initialize the Root Signer configuration.

        :param file_name: Name of the configuration file.
        """
        super().__init__(file_name)
        self._secure_dirs.append("passphrases")
        self.set_config()

    @property
    def passphrases(self) -> str:
        """
        The path to the directory where passphrases are stored **(ro)**.

        :returns: The directory path for passphrase files.
        """
        return self._raw_data["passphrases"]

    @property
    def ext_chain(self) -> str:
        """
        The file extension for certificate chain files **(ro)**.

        :returns: The configured extension for chains.
        """
        return self._raw_data["ext_chain"]

    def as_path(self, read_only: bool = True) -> RootSignPathConfigPathesProtocol:
        """
        Return the configuration paths as a structured object.

        :param read_only: If True, returns a NamedTuple (ro), 
                          otherwise a SimpleNamespace (rw).
        :returns: An object providing access to all directory Path objects.
        """
        return cast(RootSignPathConfigPathesProtocol,super().as_path(read_only))


# !CLASS - Root Signer Configuration


# CLASS - Intermediate Configuration
class IntermedPKIConfig(RootSignerPKIConfig):
    """
    Configuration class for Intermediate Certificate Authorities.

    This class extends the Root Signer configuration to include
    certificate policies and specific policy file extensions.
    """
    def __init__(self, file_name: str | None = "intermed.toml") -> None:
        """
        Initialize the Intermediate CA configuration.

        :param file_name: Name of the configuration file.
        """
        super().__init__(file_name)

    @property
    def policies(self) -> str:
        """
        The path to the directory where certificate policies are stored **(ro)**.

        :returns: The directory path for policy files.
        """
        return self._raw_data["policies"]

    @property
    def ext_policy(self) -> str:
        """
        The file extension for certificate policy files **(ro)**.

        :returns: The configured extension for policies.
        """
        return self._raw_data["ext_policy"]

    def as_path(self, read_only: bool = True) -> IntermedPathConfigPathesProtocol:
        """
        Return the configuration paths as a structured object.

        :param read_only: If True, returns a NamedTuple (ro), 
                          otherwise a SimpleNamespace (rw).
        :returns: An object providing access to all directory Path objects.
        """
        return cast(IntermedPathConfigPathesProtocol,super().as_path(read_only))


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
        "get_started_configuration.rst",
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
