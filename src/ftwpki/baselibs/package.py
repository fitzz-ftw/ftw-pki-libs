# File: src/ftwpki/baselibs/package.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
package
===============================


Modul package documentation
"""

import io
import zipfile
from pathlib import Path
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from ftwpki.baselibs.core import extract_certs_from_chain, load_certificate_from_pem
from ftwpki.baselibs.transport import (
    RSAPrivateKey,
    decrypt_transport_package,
    encrypt_bytedata,
    validate_and_format_chain,
)


# CLASS - PKIPackage:
class PKIPackage:
    """
    A container for handling PKI package data, including certificates and files.

    This class manages the lifecycle of a PKI package, providing methods to
    load, save, encrypt, and decrypt package contents.
    """
    def __init__(self) -> None:
        """
        Initialize a new instance of PKIPackage.
        """
        self._file_content:bytes=b''
        self._private_key: RSAPrivateKey = cast(RSAPrivateKey, None)
        self._encrypted:bool = False
        self._new_signed_certificate:bool= False
        self._file_path: Path | None = None

        self._data: dict[str, x509.Certificate] = {
            "ca.crt.pem": cast(x509.Certificate, None),
            "user.crt.pem": cast(x509.Certificate, None),
            "caroot.crt.pem": cast(x509.Certificate, None),
        }
        self._intermediate_certs: list[x509.Certificate] = []

        self._additional_files:dict[str,Any]={}
        self._message:str=""



    @property
    def recipient_cert(self) -> x509.Certificate:
        """
        Get the recipient certificate **(rw)**.

        :param value: The certificate to be set as recipient certificate.
        :raises ValueError: If the setter is called with an invalid certificate (Setter).
        :returns: The currently stored recipient certificate.
        """
        return self._data["user.crt.pem"]
    
    @recipient_cert.setter
    def recipient_cert(self, value:x509.Certificate) -> None:
        """
        Get the recipient certificate **(rw)**.

        :param value: The certificate to be set as recipient certificate.
        :raises ValueError: If the setter is called with an invalid certificate (Setter).
        :returns: The currently stored recipient certificate.
        """
        if self._data["user.crt.pem"] is None or self._data["user.crt.pem"] != value:
            self._new_signed_certificate =True
            self._data["user.crt.pem"] = value

    @property
    def ca_cert(self) -> x509.Certificate:
        """
        Get the CA certificate **(rw)**.

        :param value: The certificate to be set as CA certificate.
        :raises ValueError: If the provided certificate is invalid (Setter).
        :returns: The stored CA certificate.
        """
        return self._data["ca.crt.pem"]

    @ca_cert.setter
    def ca_cert(self, value: x509.Certificate) -> None:
        """
        Get the CA certificate **(rw)**.

        :param value: The certificate to be set as CA certificate.
        :raises ValueError: If the provided certificate is invalid (Setter).
        :returns: The stored CA certificate.
        """
        self._data["ca.crt.pem"] = value

    @property
    def caroot_cert(self) -> x509.Certificate:
        """
        Get the root certificate **(rw)**.

        :param value: The certificate to be set as root certificate.
        :raises ValueError: If the provided certificate is invalid (Setter).
        :returns: The stored root certificate.
        """
        return self._data["caroot.crt.pem"]
    
    @caroot_cert.setter
    def caroot_cert(self, value:x509.Certificate) -> None:
        """
        Get the root certificate **(rw)**.

        :param value: The certificate to be set as root certificate.
        :raises ValueError: If the provided certificate is invalid (Setter).
        :returns: The stored root certificate.
        """
        self._data["caroot.crt.pem"] = value
    
    @property
    def private_key(self) -> RSAPrivateKey:
        """
        Get the private key **(rw)**.

        :param value: The private key to be assigned.
        :raises ValueError: If the key is not yet assigned or invalid (Setter).
        :returns: The assigned private key.
        """
        if self._private_key is None:
            raise ValueError("PKIPackage: Private Key wurde noch nicht zugewiesen.")
        return self._private_key

    @private_key.setter
    def private_key(self,value:RSAPrivateKey) -> None:
        """
        Get the private key **(rw)**.

        :param value: The private key to be assigned.
        :raises ValueError: If the key is not yet assigned or invalid (Setter).
        :returns: The assigned private key.
        """
        self._private_key = value

    @property
    def has_private_key(self)-> bool:
        """
        Check if a private key is present **(ro)**.

        :returns: True if a private key is stored, False otherwise.
        """
        return self._private_key is not None

    @property
    def to_encrypt(self) -> bool:
        """
        Get the encryption status **(rw)**.

        :param value: The boolean status to enable or disable encryption.
        :returns: True if encryption is enabled, False otherwise.
        """
        return self._encrypted

    @to_encrypt.setter
    def to_encrypt(self, value:bool)->None:
        """
        Get the encryption status **(rw)**.

        :param value: The boolean status to enable or disable encryption.
        :returns: True if encryption is enabled, False otherwise.
        """
        self._encrypted=value

    @property
    def message(self) -> str:
        """
        Get the message string **(rw)**.

        :param value: The text message to store.
        :returns: The currently stored message.
        """
        return self._message

    @message.setter
    def message(self, value:str) -> None:
        """
        Get the message string **(rw)**.

        :param value: The text message to store.
        :returns: The currently stored message.
        """
        self._message = value

    @message.deleter
    def message(self) -> None:
        """
        Delete the stored message.
        """
        self._message= ""

    @property
    def additional_files(self)->dict[str, Any]:
        """
        Get the dictionary of additional files **(ro)**.

        :returns: A dictionary containing filenames and their content.
        """
        return self._additional_files

    @additional_files.deleter
    def additional_files(self)->None:
        """
        Delete all additional files.
        """
        self._additional_files={}

    def load(self, file_path:str|Path) -> None:
        """
        Load package data from a specified file path.

        :param file_path: The path to the package file to load.
        :raises FileNotFoundError: If the file does not exist.
        """
        self._file_path = Path(file_path)
        self._file_content: bytes = self._file_path.read_bytes()
        self.decrypt() if b'smime.p7m' in self._file_content else ...
        with zipfile.ZipFile(io.BytesIO(self._file_content)) as zf:
            for file_ in zf.namelist():
                if file_ in self._data:
                    self._data[file_] = load_certificate_from_pem(zf.read(file_))
                elif file_ == "full.chain.pem":
                    self._intermediate_certs = extract_certs_from_chain(zf.read(file_))
                elif file_ == "intermed.chain.pem":
                    self._old_intermediats_certs = extract_certs_from_chain(zf.read(file_))
                elif file_ == "message.txt":
                    self._message = str(zf.read(file_).decode("utf-8"))
                else:
                    self._additional_files[file_]= zf.read(file_)

    def save(self, file_path: str | Path|None = None) -> None:
        """
        Save the package data to a file.

        :param file_path: Optional destination path. If not provided, the internal path is used.
        :raises ValueError: If no valid file path is provided or determined.
        """
        target_path = Path(file_path) if file_path else self._file_path
        if not target_path:
            raise ValueError("Kein Pfad zum Speichern angegeben.")
        if not self._intermediate_certs:
            self._intermediate_certs.append(self._data["caroot.crt.pem"])

        intermediate_pems = [c.public_bytes(Encoding.PEM) 
                             for c in self._intermediate_certs] 

        if self._new_signed_certificate:
            full_chain = validate_and_format_chain(
                self._data["user.crt.pem"].public_bytes(Encoding.PEM),
                *intermediate_pems, 
                )

            intermediate_pems = validate_and_format_chain(
                *intermediate_pems
            )
        else:
            full_chain = validate_and_format_chain(
                *intermediate_pems,
            )

            intermediate_pems = validate_and_format_chain(*intermediate_pems[1:])

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for k, v in self._data.items():
                zf.writestr(k, v.public_bytes(Encoding.PEM)) if v else ...
            zf.writestr("full.chain.pem", full_chain)
            zf.writestr("intermed.chain.pem", intermediate_pems)
            if self._message:
                zf.writestr("message.txt", self._message)

            for fname, content in self._additional_files.items():
                zf.writestr(fname, content)

        self._file_content = zip_buffer.getvalue()

        self.encrypt() if self._encrypted else ...
        target_path = target_path.with_suffix(".spki" if self._encrypted else ".pki")
        target_path.write_bytes(self._file_content)


    def encrypt(self) -> None:
        """
        Encrypt the package content.
        """
        self._file_content = encrypt_bytedata(
            unencrypted_data=self._file_content,
            recipient_cert=self._data["user.crt.pem"],
            ca_key=self._private_key,
        )
        

    def decrypt(self) -> None:
        """
        Decrypt the package content.
        """
        self._file_content = decrypt_transport_package(self._file_content, 
                                                       self._private_key)
        self._encrypted = True

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"

# !CLASS - PKIPackage:


if __name__ == "__main__": # pragma: no cover
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
        "get_started_package.rst",
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
                print(f"\nKeep going! You already passed {passed_files} files "
                  f"with {test_sum} tests before this hit.")                
                break  # Stop on first failure if FAIL_FAST is set
            passed_files += 1
        else:
            print(f"⚠️ Warning: Test file {test_file.name} not found.")
    if test_failed == 0:
        print(f"\nDocTests passed without errors, {test_sum} tests.")
    else:
        if not option_flags & FAIL_FAST:
            print(f"\nDocTests failed: {test_failed} tests out of {test_sum}.")
