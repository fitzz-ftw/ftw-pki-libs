# File: src/ftwpki/baselibs/configuration.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
configuration
===============================


Modul configuration documentation
"""

from copy import deepcopy
from pathlib import Path
from typing import Any

from cryptography import x509

from ftwpki.baselibs.app_dirs import config_file_path, create_app_pathes
from ftwpki.baselibs.config_file_create import (
    MAIN_CONFIG,
    write_example_config,
)
from ftwpki.baselibs.package import PKIPackage
from ftwpki.baselibs.protocols import (
    PathCategoryType,
)
from ftwpki.baselibs.toml_utils import _get_toml_policy_data, toml2config


# CLASS - BasePKIConfig
class BasePKIConfig:
    def __init__(self, file_name: str="test") -> None:
        """
        Initialize the configuration directly from a file.

        :param file_name: Name of the configuration file.
        :raises PermissionError: If there are insufficient rights to create
                                 the configuration or directories.
        """
        self._mainconfig:Path = config_file_path()
        self._file_name: Path = Path(file_name).with_suffix(".pki")
        self._path: Path = self._mainconfig
        self._pki_conf = PKIPackage()
        if not self._mainconfig.is_file():
            main_content = MAIN_CONFIG
            write_example_config(main_content)
        self._secure_dirs: list[str] = ["private_keys"]
        self._usable = {"set_config": False,
                        "set_file_name": bool(file_name), 
                        "handel_pki_file":False}


    #DOC - new
    def set_file_name(self, value:str| Path):
        self._file_name: Path = Path(value).with_suffix(".pki")
        self._usable["set_filename"] = True



    def set_config(self, section: str = "") -> None:
        """
        Load configuration data from a TOML section and initialize application paths.

        This method fetches the raw configuration data for the specified section,
        injects default path keys, and generates the internal secure path mappings.

        :param section: The section name within the TOML file. If empty, the
                        default or root configuration is used.
        """
        self._raw_data: dict[str, str] = toml2config(section=section)
        dirs_to_setup: list[str] = [k for k,v in self._raw_data.items() if not v=="#zip#"]
        self._raw_data["config_path"] = "#config#"
        self._raw_data["data_path"] = "#data#"
        dirs_to_setup.extend(["config_path", "data_path"])
        self._paths: dict[str, Path] = create_app_pathes(
             self._raw_data, self._secure_dirs, *dirs_to_setup
        )
        self._in_zip: list[str] = [k for k, v in self._raw_data.items() if v == "#zip#"]
        self._usable["set_config"] = True

    #DOC - new
    def init_completed(self) -> dict[str, bool]:
        return self._usable.copy()

    @property
    def in_zip(self) -> list[str]:
        return self._in_zip

    @property
    def pki_path(self):
        return self._paths["zip"]

    @property
    def passphrases_path(self) -> Path|None:
        return self._paths.get("passphrases", None)

    def handle_pki_file(self) -> None:
        if not (self.pki_path / self._file_name).is_file():
            self._pki_conf.load(self._file_name)
            passphrase_conf_file = self._pki_conf.message
            if (
                passphrase_conf_file
                and self.passphrases_path
                and self._pki_conf.additional_files[passphrase_conf_file]
            ):
                (self.passphrases_path / passphrase_conf_file).write_bytes(
                    self._pki_conf.additional_files[passphrase_conf_file]
                )
                del self._pki_conf.additional_files[passphrase_conf_file]
                del self._pki_conf.message
            self._pki_conf.to_encrypt = False
            self._pki_conf.save(self.pki_path/ self._file_name)
            self._file_name.unlink(True)
        self._pki_conf.load(self.pki_path / self._file_name)
        self._usable["handle_pki_file"] = True

    #DOC - new
    def __bool__(self) -> bool:
        return all(self._usable.values())

    @property
    def config_path(self) -> Path:
        """
        The absolute path to the application configuration directory **(ro)**.

        :returns: The configuration directory path.
        """
        return self._paths["config_path"]

    @property
    def data_path(self) -> Path:
        """
        The absolute path to the application data directory **(ro)**.

        :returns: The data directory path.
        """
        return self._paths["data_path"]

    @property
    def private_keys(self) -> Path:
        """
        The path to the private keys directory **(ro)**.

        :returns: The directory path as defined in the configuration.
        """
        return self._paths.get("private_keys", self.pki_path)

    def private_key(self, key_name: str) -> bytes:
        return self.private_keys.joinpath(key_name).read_bytes()

    @property
    def public_data(self) -> Path:
        """
        The path to the public data directory **(ro)**.

        :returns: The directory path for public files.
        """
        return self._paths["data_path"]

    #DOC - 
    @property
    def fullchain(self) -> list[x509.Certificate]:
        return self._pki_conf.fullchain if "chains" in self.in_zip else []

    @property
    def own_cert(self)->x509.Certificate:
        return self._pki_conf._data["user.crt.pem"]

    def get_certs(self)->dict[str, x509.Certificate]:
        return self._pki_conf._data
    
    #DOC - new
    @property
    def pki(self) -> PKIPackage:
        return self._pki_conf

    def resolve(self, name: str, category: PathCategoryType | None = None) -> Path:
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
        if p.is_absolute() or name.startswith("/") or name.startswith("\\"):
            return p
        if category:
            base = self._paths.get(category)
            if base is None:
                raise KeyError(f"Pfad-Kategorie '{category}' nicht konfiguriert.")

            return base / p
        else:
            return Path(name).expanduser().resolve()

    @property
    def current_configfile_entries(self) -> dict[str, Any]:
        """The entries of the configuration file for this configuration **(ro)**.

        :return: A deepcopy of the dictionary with the entries.
        """
        return deepcopy(self._raw_data)

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

    def __init__(self, file_name: str = "user.toml") -> None:
        """
        Initialize the User PKI configuration.

        :param file_name: Name of the configuration file.
        """
        super().__init__(file_name)
        self.set_config()


# !CLASS - UserPKIConfig


# CLASS - Leaf Configuration
class LeafPKIConfig(BasePKIConfig):
    """
    Configuration class for leaf applications.

    This class provides settings for clients, servers, and client-server
    applications that interact within the PKI infrastructure.
    """

    def __init__(self, file_name: str  = "leaf.toml") -> None:
        """
        Initialize the Leaf PKI configuration.

        :param file_name: Name of the configuration file.
        """
        super().__init__(file_name )
        self.set_config()


# !CLASS - Leaf Configuration


# CLASS - Root Signer Configuration
class RootSignerPKIConfig(BasePKIConfig):
    """
    Configuration class for Root Signer applications.

    This class handles settings for Root CAs and signing entities,
    including secure storage for passphrases and chain extensions.
    """

    def __init__(self, file_name: str = "rsign.toml", section:str="caroot") -> None:
        """
        Initialize the Root Signer configuration.

        :param file_name: Name of the configuration file.
        """
        super().__init__(file_name)
        self._secure_dirs.append("passphrases")
        self.set_config(section=section)

    def private_key(self, key_name: str="CA.key.pem") -> bytes:
        if "private_keys" in self.in_zip:
            return self._pki_conf.additional_files[key_name]
        else:
            return self.private_keys.joinpath(key_name).read_bytes()

    @property
    def passphrases(self) -> Path:
        """
        The path to the directory where passphrases are stored **(ro)**.

        :returns: The directory path for passphrase files.
        """
        return self._paths["passphrases"]


    @property
    def policy_files(self):
        return [f for f in self._pki_conf.additional_files.keys() if f.endswith(".policy")]

    def get_dn_policies(self, policyname: str, section: str = ""):
        toml = self._pki_conf.additional_files[policyname].decode("utf-8")
        return _get_toml_policy_data("dn", file_content=toml, section=section)

    def get_extentions(self, policyname:str, section:str=""):
        toml = self._pki_conf.additional_files[policyname].decode("utf-8")
        return _get_toml_policy_data("ext", file_content=toml, section=section)


# !CLASS - Root Signer Configuration

# CLASS - Intermediate Configuration
class IntermedPKIConfig(RootSignerPKIConfig):
    """
    Configuration class for Intermediate Certificate Authorities.

    This class extends the Root Signer configuration to include
    certificate policies and specific policy file extensions.
    """

    def __init__(self, file_name: str = "intermediate", section:str="intermediate") -> None:
        """
        Initialize the Intermediate CA configuration.

        :param file_name: Name of the configuration file.
        """
        super().__init__(file_name, section=section)

    @property
    def policies(self) -> Path|None:
        """
        The path to the directory where certificate policies are stored **(ro)**.

        :returns: The directory path for policy files.
        """
        return self._paths.get("policies", self._paths.get("zip"))
        

    @property
    def ext_policy(self) -> str:
        """
        The file extension for certificate policy files **(ro)**.

        :returns: The configured extension for policies.
        """
        return ".policy"

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
        # "get_started_develop_config_reader.rst"
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
