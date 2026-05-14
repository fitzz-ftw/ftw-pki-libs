# File: src/ftwpki/baselibs/passwd.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2.1
"""
Password and Secret Encryption Management
=========================================

This module provides a secure manager for handling PKI secrets and
passphrases. It implements AES-256-CBC encryption with PBKDF2 key
derivation, ensuring full compatibility with OpenSSL's 'salted' file
format. (rw)

Main Features:
    * AES-256-CBC encryption for sensitive password files.
    * PBKDF2-HMAC-SHA256 key derivation (100k iterations).
    * Enforcement of restricted file system permissions (owner-only).
    * OpenSSL-compatible ``Salted__`` header handling.
"""

import os
import stat
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ftwpki.baselibs.exceptions import PKIEncryptionError, PKISecurityError


class PasswordManager:
    """
    Manager for native encryption of PKI secrets. (rw)

    This class handles the lifecycle of encrypted passphrase files. It
    uses a master password to derive cryptographic keys and manages
    secure storage within a dedicated private directory.
    """

    def __init__(self, private_dir: str = "./private") -> None:
        """
        Initialize the manager and set encryption parameters. (rw)

        :param private_dir: Path to the directory where encrypted files
                            are stored.
        """
        self._private_dir = Path(private_dir)
        self._iterations = 100_000
        self._salt_size = 8

    @property
    def private_dir(self) -> Path:
        """
        Return the resolved path of the private directory. (ro)

        :returns: The Path object of the internal private storage location.
        """
        return self._private_dir

    def encrypt_password_file(self, input_file: str, output_filename: str, password: str) -> None:
        """
        Encrypt a source file into an OpenSSL-compatible format. (rw)

        Reads a raw password file, applies PKCS7 padding, and encrypts it
        using AES-256-CBC. The output includes the ``Salted__`` header and
        an 8-byte random salt. The resulting file is secured with
        owner-only permissions.

        :param input_file: The path to the unencrypted source file.
        :param output_filename: Target name within the private_dir.
        :param password: The master password for key derivation.
        :raises FileNotFoundError: If the input file is missing or empty.
        :raises PKIEncryptionError: If the encryption process fails.
        """
        in_path = Path(input_file)
        if not in_path.exists() or in_path.stat().st_size == 0:
            raise FileNotFoundError(f"Input file {input_file} is missing or empty.")

        try:
            self._private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            out_path = self._private_dir / output_filename
            salt = os.urandom(self._salt_size)

            key, iv = self._derive_key_iv(password, salt)

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
        Decrypt an encrypted file and return the stored passphrase. (rw)

        Validates the ``Salted__`` header, derives the key from the
        embedded salt, and performs AES decryption followed by PKCS7
        unpadding.

        :param encrypted_filename: Name of the file in the private_dir.
        :param password: The master password for decryption.
        :raises FileNotFoundError: If the encrypted file is missing.
        :raises PKISecurityError: If the format is invalid or decryption
                                  fails.
        :returns: The decrypted passphrase as a string.
        """
        file_path = self._private_dir / encrypted_filename
        if not file_path.exists():
            raise FileNotFoundError(f"Encrypted file {encrypted_filename} not found.")

        try:
            raw_data = file_path.read_bytes().rstrip(b"\r\n \x00")

            if not raw_data.startswith(b"Salted__"):
                raise PKISecurityError()

            salt = raw_data[8:16]
            ciphertext = raw_data[16:]

            key, iv = self._derive_key_iv(password, salt)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()

            pad_len = padded_data[-1]
            if ((pad_len < 1 or pad_len > 16)
                or (padded_data[-pad_len:] != bytes([pad_len] * pad_len))):
                raise PKISecurityError("Invalid padding length or content mismatch")

            # if padded_data[-pad_len:] != bytes([pad_len] * pad_len):
            #     raise PKISecurityError("Padding content mismatch")

            decrypted_data = padded_data[:-pad_len]
            return decrypted_data.decode("utf-8")

        except Exception as err:
            raise PKISecurityError() from err

    def _set_restricted_permissions(self, file_path: Path) -> None:
        """
        Enforce restricted file system permissions (0o600). (rw)

        :param file_path: Path to the file requiring protection.
        """
        file_path.chmod(stat.S_IREAD | stat.S_IWRITE)

    def _derive_key_iv(self, password: str, salt: bytes) -> tuple[bytes, bytes]:
        """
        Derive AES key and IV using PBKDF2-HMAC-SHA256. (rw)

        :param password: The master password string.
        :param salt: The 8-byte salt for derivation.
        :returns: A tuple containing the 32-byte key and 16-byte IV.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=48,
            salt=salt,
            iterations=self._iterations,
            backend=default_backend(),
        )
        derived = kdf.derive(password.encode("utf-8"))
        return derived[:32], derived[32:]

    def __repr__(self) -> str:
        """
        Return a formal representation of the PasswordManager. (rw)

        :returns: String containing the class name and private directory.
        """
        return f"{self.__class__.__name__}(private_dir={str(self._private_dir)!r})"
    
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
