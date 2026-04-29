# File: src/ftwpki/baselibs/openssl_comp.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
OpenSSL Compatibility and Database Management
=============================================

This module provides tools for maintaining compatibility with OpenSSL
file formats and CLI commands. It includes a manager for 'index.txt'
database files and wrappers for S/MIME decryption and certificate
inspection via the OpenSSL binary. (rw)

Main Features:
    * Management of OpenSSL-compliant index databases.
    * Support for certificate revocation and record tracking.
    * CLI wrappers for advanced cryptographic operations not covered
      by native libraries.
"""

import shutil
import subprocess
from pathlib import Path

from ftwpki.baselibs.core import revoke_record
from ftwpki.baselibs.data import CertificateRecord


class DbOpensslFile:
    """
    Manager for OpenSSL-style 'index.txt' database files. (rw)

    This class handles the reading, writing, and updating of certificate
    records while preserving comments and formatting within the file.
    It ensures that serial numbers remain unique and manages automatic
    backups (.old) during write operations.
    """

    def __init__(self, path: Path):
        """
        Initialize the database handler and ensure the file exists. (rw)

        :param path: The file system path to the index.txt file.
        """
        self._path = path
        if not self._path.exists():
            self._path.touch()

    def _load_data(self) -> dict[int, str | CertificateRecord]:
        """
        Read the database file into a line-mapped dictionary. (rw)

        Each line is stored by its index. Comments and empty lines are
        kept as raw strings, while valid entries are parsed into
        CertificateRecord objects.

        :returns: A dictionary mapping line numbers to records or strings.
        """
        data = {}
        lines = self._path.read_text(encoding="utf-8").splitlines()

        for i, line in enumerate(lines):
            if not line.strip() or line.startswith("#"):
                data[i] = line
            else:
                try:
                    data[i] = self._parse_line(line)
                except Exception:
                    data[i] = line
        return data

    def _save_data(self, data: dict[int, str | CertificateRecord]) -> None:
        """
        Write the current data state back to the file system. (rw)

        Creates a backup of the existing file before overwriting.
        Records are transcribed back into the tab-separated format.

        :param data: The line-mapped dictionary to persist.
        """
        shutil.copy2(self._path, self._path.with_suffix(self._path.suffix + ".old"))

        output = []
        for i in sorted(data.keys()):
            item = data[i]
            if isinstance(item, CertificateRecord):
                output.append(item.openssl_index_line)
            else:
                output.append(str(item))

        self._path.write_text("\n".join(output) + "\n", encoding="utf-8")

    def add_record(self, record: CertificateRecord) -> None:
        """
        Append a new certificate record to the database. (rw)

        :param record: The CertificateRecord to add.
        :raises ValueError: If a record with the same serial already exists.
        """
        data = self._load_data()
        if any(
            isinstance(r, CertificateRecord) and r.serial == record.serial for r in data.values()
        ):
            raise ValueError(f"Serial {record.serial} exists.")

        next_idx = max(data.keys()) + 1 if data else 0
        data[next_idx] = record
        self._save_data(data)

    def _parse_line(self, line: str) -> CertificateRecord:
        """
        Parse a single tab-separated line into a record. (rw)

        :param line: A raw line from the index.txt file.
        :returns: A validated CertificateRecord object.
        """
        import datetime

        parts = line.strip().split("\t")
        if parts[0] == "R":
            expiry_str = parts[2]
            rev_info = parts[1]
        else:
            expiry_str = parts[1]
            rev_info = ""

        expiry_dt = datetime.datetime.strptime(expiry_str, "%y%m%d%H%M%SZ").replace(
            tzinfo=datetime.timezone.utc
        )
        return CertificateRecord(
            status=parts[0],  # type: ignore
            expiry=expiry_dt,
            revocation_date=rev_info,
            serial=parts[3],
            filename=parts[4],
            subject=parts[5],
        )

    def find_active_by_subject(self, search_term: str) -> list[CertificateRecord]:
        """
        Search for active certificates matching a subject string. (ro)

        This is a read-only search through the current database state.
        Only certificates with status 'V' (Valid) are considered.

        :param search_term: Substring to search for in the certificate subject.
        :returns: A list of matching CertificateRecord objects.
        """
        data = self._load_data()
        search_term = search_term.lower()

        results = [
            item
            for item in data.values()
            if isinstance(item, CertificateRecord)
            and item.status == "V"
            and search_term in item.subject.lower()
        ]
        return results

    def revoke_by_serial(self, serial: str, reason: str = "") -> None:
        """
        Revoke a certificate identified by its serial number. (rw)

        Updates the status of the record to 'R' and attaches revocation
        metadata. The changes are immediately persisted to the file.

        :param serial: The hexadecimal serial number of the certificate.
        :param reason: Optional string describing the reason for revocation.
        :raises ValueError: If the certificate is not found or already revoked.
        """
        data = self._load_data()
        found = False
        serial_hex = serial.upper()

        for idx, item in data.items():
            if isinstance(item, CertificateRecord) and item.serial == serial_hex:
                if item.status == "V":
                    data[idx] = revoke_record(item, reason)
                    found = True
                    break
                else:
                    raise ValueError(
                        f"Zertifikat {serial_hex} ist bereits im Status {item.status}."
                    )

        if not found:
            raise ValueError(f"Kein aktives Zertifikat mit Serial {serial_hex} gefunden.")

        self._save_data(data)

    def get_revoked_records(self) -> list[CertificateRecord]:
        """
        Return all records with revoked status. (ro)

        :returns: A list of CertificateRecord objects with status 'R'.
        """
        data = self._load_data()
        return [r for r in data.values() if isinstance(r, CertificateRecord) and r.status == "R"]

    def __repr__(self) -> str:
        """
        Return a formal representation of the database handler. (rw)

        :returns: String containing the class name and file path.
        """
        return f"{self.__class__.__name__}(DBFile: {self._path.as_posix()})"


def get_cert_text(pem_path: str | Path) -> str:  # not Windows testable
    """
    Retrieve human-readable certificate details via OpenSSL. (rw)

    Executes an external 'openssl x509' process to parse the PEM file.

    *Note: An 'openssl' executable must be available in the system PATH.*

    :param pem_path: Path to the certificate file.
    :returns: The standard output of the OpenSSL command.
    """
    result = subprocess.run(
        ["openssl", "x509", "-in", pem_path, "-text", "-noout"], capture_output=True, text=True
    )
    return result.stdout


def openssl_decrypt_smime_file(input_file: str, key_file: str, password: str) -> bool:  # not Windows testable
    """
    Decrypt an S/MIME file using the OpenSSL binary. (rw)

    This function triggers an external decryption process. It expects
    a password via standard input and writes the decrypted content
    to a file (removing the '.enc' suffix if present).

    *Note: An 'openssl' executable must be available in the system PATH.*

    :param input_file: Path to the encrypted file.
    :param key_file: Path to the recipient's private key.
    :param password: The passphrase for the private key.
    :returns: True if the output file was successfully created.
    """
    # ... (Rest der Funktion wie bisher)
    output_file = input_file.rstrip(".enc")
    if output_file == input_file:
        output_file += ".dec"

    cmd = [
        "openssl",
        "smime",
        "-decrypt",
        "-binary",
        "-in",
        input_file,
        "-inkey",
        key_file,
        "-out",
        output_file,
        "-passin",
        "stdin",
    ]

    try:
        result = subprocess.run(
            cmd, input=password.encode("utf-8"), capture_output=True, check=False
        )

        if result.returncode != 0:
            print(f"OpenSSL Error: {result.stderr.decode('utf-8')}")
            return False

        return Path(output_file).exists()

    except Exception as e:
        print(f"Fehler beim OpenSSL-Aufruf: {e}")
        return False


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
    test_file = testfiles_dir / "get_started_openssl_comp.rst"
    
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
