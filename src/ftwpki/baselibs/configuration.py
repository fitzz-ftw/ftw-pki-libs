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

from ftwpki.baselibs.app_dirs import config_file_path, create_app_pathes, get_uni_path
from ftwpki.baselibs.config_file_create import (
    INTERMED_CONFIG,
    LEAF_CONFIG,
    MAIN_CONFIG,
    MAIN_CONFIG_DEV,
    ROOT_SIGNER_CONFIG,
    USER_CONFIG,
    toml_conf_str,
    write_example_config,
)
from ftwpki.baselibs.package import PKIPackage
from ftwpki.baselibs.protocols import (
    ConfigTypeName,
    PathCategoryType,
)
from ftwpki.baselibs.toml_utils import _get_toml_policy_data_DEV, toml2config


# CLASS - ReadPKIConfig
class ReaderPKIConfig:
    """
    Reader for dynamic multi-tier PKI configuration layouts.
    """
    # DOC - change?
    def __init__(self, file_name: str | None = None) -> None:
        """
        Initialize the multi-tier PKI configuration reader.

        :param file_name: Optional custom configuration file name.
        """
        self._mainconfig = config_file_path()
        self._file_name = file_name
        if not self._mainconfig.is_file():
            main_content = MAIN_CONFIG.format(file_name=file_name)
            write_example_config(main_content)
        self._paths:dict[str,Path] = {} #cast(dict[str,Path],{})
        self._raw_data: dict[str, str] = {} #cast(dict[str, str], {})
        self._conf_type: ConfigTypeName = None
        self._configmain:dict[str,str] = {}

    def read_main_config(self) -> None:
        """
        Read and load the main application configuration mapping.
        """
        self._configmain = toml2config()
    
    def read_config(self, name:str="") -> None:
        """
        Load a specific tier configuration and resolve directory paths.

        :param name: The name of the PKI tier or direct configuration file.
        """
        if not self._configmain:
            self.read_main_config()

        # Resolve tier name or use default target config from main layout
        tier_target = name if name else self.default_config
        # Resolve mapped file name (e.g., "intermediate" -> "intermed.toml")
        # If it's already a direct file name containing a dot, keep it as is
        if "." in tier_target:
            config_file = tier_target
        else:
            config_file = self._configmain.get(tier_target, self.default_config)
        self._raw_data = toml2config(file_name=config_file)
        pathes = [k for k in self._raw_data if not k.startswith("ext")]
        for path_ in pathes:
            self._paths[path_]= get_uni_path(self._raw_data[path_])
        
        if "policies" in self._raw_data:
            self._conf_type = "intermediate"
        elif "passphrases" in self._raw_data:
            self._conf_type = "root"
        else:
            self._conf_type = "leaf"

    def list_mainconfig(self) -> dict[str, str]:
        """
        Get the main configuration map excluding the default tier key.

        :returns: A dictionary of the filtered main configuration settings.
        """
        return {k: v for k,v in self._configmain.items() if k != "default_config" }

    #SECTION - Properties
    @property
    def config_type(self)->ConfigTypeName:
        """
        Get the detected configuration type tier **(ro)**.

        :returns: The configuration type tier name.
        """
        return self._conf_type
    
    @property
    def default_config(self)->str:
        """
        Get the default configuration file name **(ro)**.

        :returns: The default configuration file name string.
        """
        return self._configmain.get("default_config", "")

    @property
    def private_keys(self) -> Path|None:
        """
        The path to the private keys directory **(ro)**.

        :returns: The directory path as defined in the configuration.
        """
        return self._paths.get("private_keys")

    @property
    def public_data(self) -> Path | None:
        """
        The path to the public data directory **(ro)**.

        :returns: The directory path for public files.
        """
        return self._paths.get("public_data")

    @property
    def certs(self) -> Path | None:
        """
        The path to the directory where certificates are stored **(ro)**.

        :returns: The directory path for certificates.
        """
        return self._paths.get("certs")

    @property
    def chains(self) -> Path | None:
        """
        The path to the directory where certificate chains are stored **(ro)**.

        :returns: The directory path for chains.
        """
        return self._paths.get("chains")

    @property
    def passphrases(self) -> Path | None:
        """
        The path to the directory where passphrases are stored **(ro)**.

        :returns: The directory path for passphrase files.
        """
        return self._paths.get("passphrases")

    @property
    def policies(self) -> Path | None:
        """
        The path to the directory where certificate policies are stored **(ro)**.

        :returns: The directory path for policy files.
        """
        return self._paths.get("policies")

    @property
    def ext_policy(self) -> str | None:
        """
        The file extension for certificate policy files **(ro)**.

        :returns: The configured extension for policies.
        """
        return self._raw_data.get("ext_policy")

    @property
    def ext_chain(self) -> str | None:
        """
        The file extension for certificate chain files **(ro)**.

        :returns: The configured extension for chains.
        """
        return self._raw_data.get("ext_chain")

    @property
    def ext_cert(self) -> str | None:
        """
        The file extension for certificate files **(ro)**.

        :returns: The configured certificate extension.
        """
        return self._raw_data.get("ext_cert")

    @property
    def ext_public(self) -> str | None:
        """
        The file extension for public data files **(ro)**.

        :returns: The configured public data extension.
        """
        return self._raw_data.get("ext_public")

    @property
    def ext_signedcert(self) -> str | None:
        """
        The file extension for signed certificates **(ro)**.

        :returns: The configured signed certificate extension.
        """
        return self._raw_data.get("ext_signedcert")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(Type={self._conf_type})"


    # !SECTION - Properties

# !CLASS - ReadPKIConfig


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
        self._mainconfig = config_file_path()
        self._file_name = file_name
        if not self._mainconfig.is_file():
            main_content = MAIN_CONFIG.format(file_name=file_name)
            write_example_config(main_content)
        self._path: Path = config_file_path(file_name=file_name)
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
            write_example_config(conf_str, file_name=file_name)

        self._secure_dirs: list[str] = ["private_keys"]
        self._raw_data: dict[str, str] = {}

        # create_app_pathes erledigt die Validierung/Erstellung
        # und gibt ein dict mit Path-Objekten zurück
        self._paths: dict[str, Path] = {}

    def set_config(self, section: str = "") -> None:
        """
        Load configuration data from a TOML section and initialize application paths.

        This method fetches the raw configuration data for the specified section,
        injects default path keys, and generates the internal secure path mappings.

        :param section: The section name within the TOML file. If empty, the
                        default or root configuration is used.
        """
        default_config: str = (
            toml2config().get("default_config", "") if not self._file_name else self._file_name
        )
        self._raw_data: dict[str, str] = toml2config(section=section, file_name=default_config)
        dirs_to_setup: list[str] = [k for k in self._raw_data if not k.startswith("ext")]
        self._raw_data["config_path"] = "#config#"
        self._raw_data["data_path"] = "#data#"
        dirs_to_setup.extend(["config_path", "data_path"])
        self._paths: dict[str, Path] = create_app_pathes(
            self._raw_data, self._secure_dirs, *dirs_to_setup
        )

    @property
    def config_path(self)->Path:
        """
        The absolute path to the application configuration directory **(ro)**.

        :returns: The configuration directory path.
        """
        return self._paths["config_path"]

    @property
    def data_path(self)->Path:
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
        return self._paths["private_keys"]

    @property
    def public_data(self) -> Path:
        """
        The path to the public data directory **(ro)**.

        :returns: The directory path for public files.
        """
        return self._paths["public_data"]

    @property
    def certs(self) -> Path:
        """
        The path to the directory where certificates are stored **(ro)**.

        :returns: The directory path for certificates.
        """
        return self._paths["certs"]

    @property
    def chains(self) -> Path:
        """
        The path to the directory where certificate chains are stored **(ro)**.

        :returns: The directory path for chains.
        """
        return self._paths["chains"]

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

# CLASS - BasePKIConfig_DEV
class BasePKIConfig_DEV:
    def __init__(self, file_name: str) -> None:
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
            main_content = MAIN_CONFIG_DEV
            write_example_config(main_content)
        self._secure_dirs: list[str] = ["private_keys"]

    def set_config(self, section: str = "") -> None:
        """
        Load configuration data from a TOML section and initialize application paths.

        This method fetches the raw configuration data for the specified section,
        injects default path keys, and generates the internal secure path mappings.

        :param section: The section name within the TOML file. If empty, the
                        default or root configuration is used.
        """
        self._raw_data: dict[str, str] = toml2config(section=section)
        # for k,v in self._raw_data.items():
        #     print(f"{k}: {v}")
        dirs_to_setup: list[str] = [k for k,v in self._raw_data.items() if not v=="#zip#"]
        self._raw_data["config_path"] = "#config#"
        self._raw_data["data_path"] = "#data#"
        dirs_to_setup.extend(["config_path", "data_path"])
        self._paths: dict[str, Path] = create_app_pathes(
             self._raw_data, self._secure_dirs, *dirs_to_setup
        )
        self._in_zip: list[str] = [k for k, v in self._raw_data.items() if v == "#zip#"]

    @property
    def in_zip(self) -> list[str]:
        return self._in_zip

    @property
    def pki_path(self):
        return self._paths["zip"]
    
    @property
    def passphrases_path(self):
        return self._paths["passphrases"]

    def handle_pki_file(self):
        if not (self.pki_path / self._file_name).is_file():
            self._pki_conf.load(self._file_name)
            passphrase_conf_file = self._pki_conf.message
            if passphrase_conf_file and self._pki_conf.additional_files[passphrase_conf_file]:
                (self.passphrases_path / passphrase_conf_file).write_bytes(
                    self._pki_conf.additional_files[passphrase_conf_file]
                )
                del self._pki_conf.additional_files[passphrase_conf_file]
                del self._pki_conf.message
            self._pki_conf.to_encrypt = False
            self._pki_conf.save(self.pki_path/ self._file_name)
            self._file_name.unlink(True)
        self._pki_conf.load(self.pki_path / self._file_name)



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
        return self._paths["public_data"]

    @property
    def fullchain(self) -> list[x509.Certificate]:
        if "chains" in self.in_zip:
            return self._pki_conf.fullchain
        return []

    @property
    def policy_files(self):
        return [f for f in self._pki_conf.additional_files.keys() if f.endswith(".policy")]

    def get_dn_policies(self, policyname:str, section:str=""):
        toml = self._pki_conf.additional_files[policyname].decode("utf-8")
        return _get_toml_policy_data_DEV("dn",file_content=toml,section=section)

    def get_extentions(self, policyname:str, section:str=""):
        toml = self._pki_conf.additional_files[policyname].decode("utf-8")
        return _get_toml_policy_data_DEV("ext", file_content=toml, section=section)

    @property
    def own_cert(self)->x509.Certificate:
        return self._pki_conf._data["user.crt.pem"]

    def get_certs(self)->dict[str, x509.Certificate]:
        return self._pki_conf._data
    
    #DOC - new
    @property
    def pki(self):
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


# !CLASS - BasePKIConfig_DEV


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
    def passphrases(self) -> Path:
        """
        The path to the directory where passphrases are stored **(ro)**.

        :returns: The directory path for passphrase files.
        """
        return self._paths["passphrases"]

    @property
    def ext_chain(self) -> str:
        """
        The file extension for certificate chain files **(ro)**.

        :returns: The configured extension for chains.
        """
        return self._raw_data["ext_chain"]


# !CLASS - Root Signer Configuration

# CLASS - Root Signer Configuration_DEV
class RootSignerPKIConfig_DEV(BasePKIConfig_DEV):
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
        return self._pki_conf.additional_files[key_name]

    @property
    def passphrases(self) -> Path:
        """
        The path to the directory where passphrases are stored **(ro)**.

        :returns: The directory path for passphrase files.
        """
        return self._paths["passphrases"]


# !CLASS - Root Signer Configuration_DEV


# CLASS - Intermediate Configuration_DEV
class IntermedPKIConfig_DEV(RootSignerPKIConfig_DEV):
    """
    Configuration class for Intermediate Certificate Authorities.

    This class extends the Root Signer configuration to include
    certificate policies and specific policy file extensions.
    """

    def __init__(self, file_name: str = "intermed.toml", section:str="intermediate") -> None:
        """
        Initialize the Intermediate CA configuration.

        :param file_name: Name of the configuration file.
        """
        super().__init__(file_name, section=section)

    @property
    def policies(self) -> Path:
        """
        The path to the directory where certificate policies are stored **(ro)**.

        :returns: The directory path for policy files.
        """
        return self._paths["policies"]

    @property
    def ext_policy(self) -> str:
        """
        The file extension for certificate policy files **(ro)**.

        :returns: The configured extension for policies.
        """
        return self._raw_data["ext_policy"]


# !CLASS - Intermediate Configuration_DEV
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
    def policies(self) -> Path:
        """
        The path to the directory where certificate policies are stored **(ro)**.

        :returns: The directory path for policy files.
        """
        return self._paths["policies"]

    @property
    def ext_policy(self) -> str:
        """
        The file extension for certificate policy files **(ro)**.

        :returns: The configured extension for policies.
        """
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
        "get_started_configuration.rst",
        "get_started_develop_config_reader.rst"
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
