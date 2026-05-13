# File: src/ftwpki/baselibs/app_dirs.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
Application Directory Management
================================

This module handles the resolution and creation of standardized application
directories across different operating systems. It ensures that
configuration files and sensitive cryptographic storage paths are correctly
initialized and secured. (rw)

Main Features:
    * Provision of platform-specific configuration and data paths.
    * Automated creation of directory structures.
    * Enforcement of restricted file system permissions (0o700) for
      security-critical paths.
"""

from pathlib import Path

from platformdirs import PlatformDirs

# FUNCTION - _pki_dirs_instance
_pki_dirs_instance = PlatformDirs(
    appname="ftwpki",
    appauthor="FitzzTeXnikWelt"
)
"""
Global instance for platform-specific directory resolution. (ro)

This internal singleton manages the mapping of abstract directory types 
(like config, cache, or logs) to the actual physical paths provided by 
the operating system. It is initialized once during module import to 
ensure consistent path handling across the application.
"""
# !FUNCTION - _pki_dirs_instance


# FUNCTION - PKIDirs
def PKIDirs() -> PlatformDirs:
    """
    Return the global platform directory handler for the application. (ro)

    This helper provides access to the pre-initialized PlatformDirs
    instance, ensuring consistent path resolution (e.g., user config,
    cache, logs) throughout the entire system.

    :returns: A PlatformDirs instance configured for 'ftwpki'.
    """
    return _pki_dirs_instance
# !FUNCTION - PKIDirs


# FUNCTION - config_file_path
def config_file_path(file_name: str|None = None) -> Path:
    """
    Return the default path to the application configuration file. (ro)

    This function resolves the location of 'pkiconfig.toml' within the
    standard user configuration directory of the operating system.

    :returns: The absolute path to the main TOML configuration file.
    """
    return PKIDirs().user_config_path / (file_name if file_name else "pkiconfig.toml")
# !FUNCTION - config_file_path

# FUNCTION - get_uni_path
def get_uni_path(logical_path: str) -> Path:
    """
    Resolve a logical path identifier to an absolute filesystem path.

    Supported formats are '#data#subpath/to/file' and '#config#subpath/to/file'.
    If the path does not start with a supported identifier, it is treated 
    as a standard relative or absolute path. 
    
    :param logical_path: The path string with an optional identifier prefix.
    :return: A pathlib.Path object pointing to the resolved location.
    """
    # Guard: Check for logical path format #identifier#
    if not (logical_path.startswith("#") and logical_path.count("#") >= 2):
        return Path(logical_path)

    parts = logical_path.split("#")
    prefix = f"#{parts[1]}#"
    rel = "#".join(parts[2:]).lstrip('/')

    if prefix == "#data#":
        base = _pki_dirs_instance.user_data_path
    elif prefix == "#config#":
        base = _pki_dirs_instance.user_config_path
    else:
        # Fallback for unknown identifiers
        return Path(logical_path)

    full_path = base / rel
    return full_path

# !FUNCTION - get_uni_path


# FUNCTION - create_app_pathes
def create_app_pathes(
    config: dict[str, str], securepathes: list[str], pathkey: str, *pathkeys: str
) -> dict[str, Path]:
    """
    Resolve and create required application directories. (rw)

    This function takes a set of keys, resolves their paths from the
    configuration, and ensures the directories exist on the file system.
    Paths identified as 'secure' are created with restricted permissions
    (0o700) to protect sensitive cryptographic material.

    :param config: Dictionary containing path strings mapped to keys.
    :param securepathes: List of keys that require restricted permissions.
    :param pathkey: The first directory key to process.
    :param pathkeys: Additional directory keys to process.
    :returns: A dictionary of resolved absolute Path objects.
    """
    keys = list(set([pathkey, *pathkeys]))
    keys.sort()
    ret = {}
    for key in keys:
        # path = Path(config[key]).expanduser().resolve()
        path = get_uni_path(config[key]).expanduser().resolve()
        if not path.exists():
            print(f"Mkdir: {path}")
            if key in securepathes:
                path.mkdir(mode=0o700, parents=True)
            else:
                path.mkdir(parents=True)
            print(f"{path.exists()=}")
        ret[key] = path
    return ret
# !FUNCTION - create_app_pathes


if __name__ == "__main__": # pragma: no cover
    from doctest import FAIL_FAST, testfile
    
    be_verbose = False
    be_verbose = True
    option_flags = 0
    option_flags = FAIL_FAST
    test_sum = 0
    test_failed = 0
    
    # Pfad zu den dokumentierenden Tests
    testfiles_dir = Path(__file__).parents[3] / "doc/source/devel"
    test_file = testfiles_dir / "get_started_app_dirs.rst"
    
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
        if test_failed == 0:
            print(f"\nDocTests passed without errors, {test_sum} tests.")
        else:
            print(f"\nDocTests failed: {test_failed} tests.")
    else:
        print(f"⚠️ Warning: Test file {test_file.name} not found.")
