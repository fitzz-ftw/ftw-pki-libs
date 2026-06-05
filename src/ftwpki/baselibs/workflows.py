# File: src/ftwpki/baselibs/workflows.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
workflows
===============================


Modul workflows documentation
"""

from pathlib import Path

from cryptography import x509
from securify.input.password import PasswordDoubleCheck

from ftwpki.baselibs.cert_request import CertificateRequest
from ftwpki.baselibs.cli_parser import ServerClientCSRParser
from ftwpki.baselibs.configuration import BasePKIConfig
from ftwpki.baselibs.core import (
    create_distinguished_name,
    generate_rsa_key_pair,
    load_private_key_from_pem,
    save_pem,
)
from ftwpki.baselibs.package import PKIPackage
from ftwpki.baselibs.policies import BasePolicy, UserPolicy
from ftwpki.baselibs.protocols import ClientTypeName, ServerClientCSRProtocol
from ftwpki.baselibs.toml_utils import toml2dn


class CSRWorkflow:
    def __init__(self) -> None:
        self._config: BasePKIConfig = BasePKIConfig()
        self._password: str = ""
        self._policy: BasePolicy = UserPolicy()
        self._config_type: ClientTypeName = "user"
        self._mandantory_san = True

    @property
    def policy(self) -> BasePolicy:
        return self._policy

    @policy.setter
    def policy(self, value: BasePolicy) -> None:
        self._policy = value

    @property
    def mandantory_san(self) -> bool:
        return self._mandantory_san

    @mandantory_san.setter
    def mandantory_san(self, value:bool)->None:
        self._mandantory_san = value

    def configuration(self, argv: list[str] | None = None):
        # SECTION - Configuration
        pre_parser = ServerClientCSRParser(add_help=False, allow_abbrev=False)
        pre_parser.mandantory_san = self.mandantory_san
        pre_args, _ = pre_parser.parse_known_args(argv)
        pre_conf ={}
        if pre_args.conf_file:
            pki_name = Path(pre_args.conf_file).stem
            pre_conf = toml2dn(Path(pre_args.conf_file).read_text())
            pre_conf["pki_name"] = pki_name
        ca_parser: ServerClientCSRParser = ServerClientCSRParser()
        ca_parser.set_defaults(**pre_conf)
        ca_parser.mandantory_san = self.mandantory_san
        self._args: ServerClientCSRProtocol = ca_parser.parse_args(argv)
        self._config.set_config(self._config_type)
        self._config.set_file_name(self._args.conf_file)
        self._password = self._args.password if self._args.password is not None else ""
        # !SECTION - Configuration

    def csr_creation(self) -> None:
        # SECTION - CSR Creation
        self._san_args = {
            "ip_addresses": self._args.ip_addresses,
            "dns_names": self._args.host_names,
        }
        subject: x509.Name = create_distinguished_name(
            country=self._args.countryName,
            state=self._args.stateOrProvinceName,
            location=self._args.localityName,
            organization=self._args.organizationName,
            common_name=self._args.commonName,
            organizational_unit=self._args.organizationalUnitName,
        )
        self._csr: CertificateRequest = CertificateRequest(
            subject=subject,
            policy=self._policy,
        )

        self._csr.verify_input_arguments(**self._san_args)

        # !SECTION - CSR Creation

    def create_password(self):
        self._password = PasswordDoubleCheck(min_delay=1.5, require_terminal=False)()

    def key_pair_creation(self) -> None:
        # SECTION - Keypair Creation
        self._private_key, _ = generate_rsa_key_pair(
            passphrase=self._password if self._password else None, key_size=4096
        )
        # !SECTION - Keypair Creation

    def save_keys(self) -> None:
        # SECTION - Save Keys
        save_pem(
            self._private_key, self._config.private_keys / self._args.private_key, is_private=True
        )
        # !SECTION - Save private Key

    def save_csr(self) -> None:
        # SECTION - Save CSR
        # san_args = {"ip_addresses": self._args.ip_addresses, "dns_names": self._args.host_names}
        if not hasattr(self, "_csr"):
            raise RuntimeError("Has no CSR initialized.\nRun 'csr_creation()' before.")
        client_pem = self._csr.build(
            load_private_key_from_pem(pem_data=self._private_key, 
                                      passphrase=self._password),
            **self._san_args,
        ).get_pem()
        save_pem(
            client_pem,
            Path(f"{self._args.pki_name + '.csr'}"),
            is_private=False,
        )
        # !SECTION - Save CSR

    def process_pki_container(self):
        # SECTION - pki- Container
        pki_pack = PKIPackage()
        self._conf_file = Path(self._args.conf_file)
        pki_pack.additional_files[f"{self._args.pki_name}.id.toml"] = self._conf_file.read_bytes()
        pki_pack.save(self._config.pki_path / self._args.pki_name)
        # !SECTION - pki- Container

    def cleanup(self) -> None:
        # SECTION - Cleanup
        self._conf_file.unlink() if self._conf_file else ...
        # !SECTION - Cleanup


# Hier den Code einfügen

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
        "workflows.rst",
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
