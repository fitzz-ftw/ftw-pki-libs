# File: src/ftwpki/baselibs/openssl_comp.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
openssl_comp
===============================


Modul openssl_comp documentation
"""

import shutil
from pathlib import Path

from ftwpki.baselibs.core import revoke_record
from ftwpki.baselibs.data import CertificateRecord


class DbOpensslFile:
    """
    Einfache index.txt Verwaltung. 
    Speichert die Datei zeilenweise, um Kommentare und Formatierung zu erhalten.
    """

    def __init__(self, path: Path):
        self._path = path
        if not self._path.exists():
            self._path.touch()

    def _load_data(self) -> dict[int, str | CertificateRecord]:
        """
        Liest die Datei in ein Dict. 
        Key: Zeilennummer, Value: Entweder der rohe String (Kommentar/Leer) 
        oder ein CertificateRecord.
        """
        data = {}
        lines = self._path.read_text(encoding="utf-8").splitlines()
        
        for i, line in enumerate(lines):
            if not line.strip() or line.startswith("#"):
                data[i] = line  # Originalzustand behalten
            else:
                try:
                    data[i] = self._parse_line(line)
                except Exception:
                    data[i] = line # Im Zweifel als Text behalten
        return data

    def _save_data(self, data: dict[int, str | CertificateRecord]) -> None:
        """Schreibt alles zurück und erstellt ein .old Backup."""
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
        """Fügt einen Record einfach am Ende an."""
        data = self._load_data()
        # Schneller Check auf Seriennummer-Duplikate
        if any(isinstance(r, CertificateRecord) 
               and r.serial == record.serial for r in data.values()):
            raise ValueError(f"Serial {record.serial} exists.")
        
        next_idx = max(data.keys()) + 1 if data else 0
        data[next_idx] = record
        self._save_data(data)

    def _parse_line(self, line: str) -> CertificateRecord:
        """Extrahiert den Record aus einer Tab-getrennten Zeile."""
        import datetime
        parts = line.strip().split("\t")
        if parts[0]=="R":
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
        Sucht nach aktiven ('V') Zertifikaten, deren Subject den Suchbegriff enthält.
        Gibt eine Liste von Records zurück, damit der User wählen kann.
        """
        data = self._load_data()
        search_term = search_term.lower()

        # Wir filtern nur nach aktiven Zertifikaten, da nur diese widerrufen werden können
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
        Widerruft ein Zertifikat EXAKT über die Seriennummer.
        Das ist der sicherste Weg, um Fehl-Revocations zu vermeiden.
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
        """Liefert alle Records mit Status 'R' für die CRL-Erstellung."""
        data = self._load_data()
        return [r for r in data.values() if isinstance(r, CertificateRecord) and r.status == "R"]

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(DBFile: {self._path.as_posix()})"

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
