# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.3a1] - 2026-05-17

### Added
- Introduce `ReaderPKIConfig` class supporting flexible multi-tier configuration layouts (leaf, root, intermediate).
- Add `ext_chain` key (defaulting to `".pem"`) to standard configuration templates and creator utilities for robust certificate chain handling.
- Introduced token-based application directory path resolutions within `create_app_pathes`.

### Changed
- Refactored `create_app_pathes` and configuration file loading routines to support logical, platform-independent dynamic path structures.
- Streamlined structural environment lookups by enforcing absolute logic paths checks across multiple POSIX and non-POSIX testing environments.
- Updated internal doctests (`get_started_app_dirs.rst`, etc.) to align with new isolated testing sandbox structures.

### Fixed
- Fixed environment leaks in test suites by hardening teardown routines, achieving a flawless 100% test coverage across Python versions 3.11 to 3.15.


## [0.0.2a1] - 2026-05-13

### Added
- Initial project structure for `ftw-pki-libs`.
- Core utilities for configuration handling and application directories.
- Support for Python 3.11 up to 3.15.
- Automated CI/CD pipeline via GitHub Actions.
- 100% test coverage requirement for all modules.
- Integrated Ruff for linting and formatting.
