# File: src/ftwpki/baselibs/passwd.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2.1
"""
passwd
===============================


Modul passwd documentation
"""


import argparse
import getpass
import os
import stat
import sys

# from getpass import getpass
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ftwpki.baselibs.exceptions import PKIEncryptionError, PKISecurityError


class PasswordManager:
    """
    Handles native encryption for PKI secrets using AES-256 and PBKDF2.
    """

    def __init__(self, private_dir: str = "./private") -> None:
        """
        Initialize the manager.

        :param private_dir: Directory for encrypted files.
        """
        self._private_dir = Path(private_dir)
        self._iterations = 100_000
        self._salt_size = 8

    @property
    def private_dir(self) -> Path:
        """
        The directory for private encrypted files **(ro)**.

        :returns: The path object of the private directory.
        """
        return self._private_dir

    def encrypt_password_file(self, input_file: str, output_filename: str, password: str) -> None:
        """
        Encrypt a file using AES-256-CBC, mimicking OpenSSL pbkdf2 behavior.

        :param input_file: The source password file.
        :param output_filename: The target filename in private_dir.
        :param password: The password used for encryption.
        :raises FileNotFoundError: If the input file is missing or empty.
        :raises EncryptionError: If the encryption process fails.
        """
        in_path = Path(input_file)
        if not in_path.exists() or in_path.stat().st_size == 0:
            raise FileNotFoundError(f"Input file {input_file} is missing or empty.")

        try:
            self._private_dir.mkdir(parents=True, exist_ok=True)
            out_path = self._private_dir / output_filename
            salt = os.urandom(self._salt_size)

            key, iv = self._derive_key_iv(password, salt)

            # Read and PKCS7 Padding
            data = in_path.read_bytes().rstrip(b"\r\n \x00")
            pad_len = 16 - (len(data) % 16)
            data += bytes([pad_len] * pad_len)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_content = encryptor.update(data) + encryptor.finalize()

            with open(out_path, "wb") as f:
                f.write(b"Salted__" + salt + encrypted_content)

            self._set_restricted_permissions(out_path)

        except Exception as err:
            raise PKIEncryptionError() from err

    def decrypt_password_file(self, encrypted_filename: str, password: str) -> str:
        """
        Decrypt an OpenSSL-compatible file and return the passphrase.

        :param encrypted_filename: The name of the file in private_dir.
        :param password: The password used to decrypt the file.
        :raises FileNotFoundError: If the encrypted file does not exist.
        :raises SecurityError: If the file format is invalid or decryption fails.
        :returns: The decrypted passphrase as a string.
        """
        file_path = self._private_dir / encrypted_filename
        if not file_path.exists():
            raise FileNotFoundError(f"Encrypted file {encrypted_filename} not found.")

        try:
            raw_data = file_path.read_bytes().rstrip(b"\r\n \x00")
            
            # OpenSSL Check: Must start with 'Salted__'
            if not raw_data.startswith(b"Salted__"):
                raise PKISecurityError()

            salt = raw_data[8:16]
            ciphertext = raw_data[16:]

            key, iv = self._derive_key_iv(password, salt)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()

            # PKCS7 Unpadding
            pad_len = padded_data[-1]
            if pad_len < 1 or pad_len > 16:
                raise PKISecurityError()
            
            decrypted_data = padded_data[:-pad_len]
            return decrypted_data.decode("utf-8")

        except Exception as err:
            raise PKISecurityError() from err

    def _set_restricted_permissions(self, file_path: Path) -> None:
        """
        Set file permissions to owner-only.

        :param file_path: Path to the file.
        """
        file_path.chmod(stat.S_IREAD | stat.S_IWRITE)

    def _derive_key_iv(self, password: str, salt: bytes) -> tuple[bytes, bytes]:
        """
        Derive Key and IV using PBKDF2-HMAC-SHA256.

        :param password: The master password.
        :param salt: The 8-byte salt.
        :returns: A tuple containing (key, iv).
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=48,
            salt=salt,
            iterations=self._iterations,
            backend=default_backend()
        )
        derived = kdf.derive(password.encode("utf-8"))
        return derived[:32], derived[32:]

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(private_dir={str(self._private_dir)!r})"

class PasswordCli:
    """
    CLI for encrypting password files using the PasswordManager.
    """

    def __init__(self):
        """
        Initialize the CLI with an argument parser.
        """
        self._parser = self._setup_parser()

    def _setup_parser(self) -> argparse.ArgumentParser:
        """
        Configure the argument parser for target, source, and output directory.

        :returns: The configured ArgumentParser instance.
        """
        parser = argparse.ArgumentParser(
            description="Encrypt a passphrase file into the private directory."
        )

        parser.add_argument("target_file", help="Name of the encrypted output file")

        parser.add_argument(
            "-p",
            "--passphrase-file",
            default="password.txt",
            help="Source file containing the passphrase (default: password.txt)",
        )

        parser.add_argument(
            "-o",
            "--outdir",
            default=".private",
            help="Target directory for encrypted files (default: .private)",
        )

        return parser

    def run(self, args_list: list[str] | None = None) -> int:
        """
        Execute the encryption process.

        :param args_list: Command line arguments.
        :returns: Exit code (0 for success, 1 for error).
        """
        args = self._parser.parse_args(args_list)
        manager = PasswordManager(private_dir=args.outdir)

        try:
            password = getpass.getpass(f"Password for '{args.target_file}': ")

            if not password:
                print("Error: Password is required.", file=sys.stderr)
                return 1

            manager.encrypt_password_file(
                input_file=args.passphrase_file,
                output_filename=args.target_file,
                password=password,
            )

            return 0

        except KeyboardInterrupt:
            return 1
        except Exception as err:
            print(f"Error: {err}", file=sys.stderr)
            return 1

    def __repr__(self) -> str:
        """
        Return the canonical string representation.

        :returns: String containing the class name.
        """
        return f"{self.__class__.__name__}()"

def get_parser() -> argparse.ArgumentParser: 
    """
    Get the argument parser for the password encryption tool.

    This function is used by Sphinx-argparse to automatically generate
    the CLI documentation.

    :return: An initialized ArgumentParser object.
    """
    cli = PasswordCli()
    return cli._setup_parser()

def prog_password_enc() -> int:
    """
    Main entry point for the password encryption command line interface.

    This function initializes the PasswordCli, parses arguments,
    and executes the encryption/decryption logic.

    :return: Exit code (0 for success, non-zero for errors).
    """
    cli = PasswordCli()
    return cli.run()


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
    test_file = testfiles_dir / "get_started_passwd.rst"
    
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
