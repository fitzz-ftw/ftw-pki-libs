import sys
from pathlib import Path

import pytest

from ftwpki.baselibs.exceptions import PKIEncryptionError, PKISecurityError
from ftwpki.baselibs.passwd import PasswordManager

# from ftwpki.baselibs.passwd import PasswordCli, prog_password_enc


def test_encrypt_password_file_raises_pki_encryption_error(tmp_path, monkeypatch):
    """
    Triggert den catch-all Block (Zeile 88-89) in encrypt_password_file.
    """
    from ftwpki.baselibs.passwd import PasswordManager
    
    # 1. Setup: Eine valide Input-Datei erstellen
    input_file = tmp_path / "secrets.txt"
    input_file.write_text("streng_geheim")
    
    # Manager initialisieren mit einem Dummy-Verzeichnis
    mgr = PasswordManager(private_dir=tmp_path / "private")
    
    # 2. Fehler provozieren: Wir sabotieren die mkdir-Methode von Path
    # (Oder wir übergeben einen Dateinamen, der unter Linux/Windows verboten ist)
    def mock_mkdir(*args, **kwargs):
        raise PermissionError("Simulierter Schreibfehler")
    
    monkeypatch.setattr(Path, "mkdir", mock_mkdir)
    
    # 3. Test: Der PermissionError wird gefangen und als PKIEncryptionError geworfen
    with pytest.raises(PKIEncryptionError):
        mgr.encrypt_password_file(
            input_file=str(input_file),
            output_filename="test.enc",
            password="test_password"
        )

def test_decrypt_invalid_header_raises_security_error(tmp_path):
    """
    Erzeugt eine Datei ohne 'Salted__' Header, um Zeile 110 zu triggern.
    """
    from ftwpki.baselibs.passwd import PasswordManager

    # 1. Setup: PasswordManager mit temporärem Verzeichnis
    mgr = PasswordManager(private_dir=tmp_path)

    # 2. Eine korrupte Datei erstellen (falscher Header)
    bad_file = tmp_path / "corrupt.enc"
    bad_file.write_bytes(b"InvalidHeader_12345")

    # 3. Versuch zu entschlüsseln -> löst Zeile 110 aus
    with pytest.raises(PKISecurityError):
        mgr.decrypt_password_file("corrupt.enc", password="any_password")

def test_decrypt_padding_error_raises_security_error(tmp_path):
    """
    Verschlüsselt eine Datei und versucht sie mit falschem Passwort zu laden,
    um die Padding-Validierung in Zeile 124 zu triggern.
    """
    from ftwpki.baselibs.passwd import PasswordManager

    # 1. Setup
    mgr = PasswordManager(private_dir=tmp_path)
    input_file = tmp_path / "secret.txt"
    input_file.write_text("Test-Daten für Padding")

    # 2. Korrekt verschlüsseln
    mgr.encrypt_password_file(str(input_file), "test.enc", password="richtiges_passwort")

    # 3. Mit falschem Passwort entschlüsseln
    # Erwartung: Hier ist es egal, welcher Teil der Kette den Fehler wirft,
    # solange es ein PKISecurityError ist.
    with pytest.raises(PKISecurityError):
        mgr.decrypt_password_file("test.enc", password="falsches_passwort")

def test_decrypt_padding_error_raises_security_error_gt16(tmp_path):
    from ftwpki.baselibs.passwd import PasswordManager

    mgr = PasswordManager(private_dir=tmp_path)
    # Datei für den Test vorbereiten
    input_file = tmp_path / "secret.txt"
    input_file.write_text("Test-Daten fuer Padding", encoding="utf-8")

    target_filename = "test.enc"
    mgr.encrypt_password_file(str(input_file), target_filename, password="password123")

    # Datei manipulieren: Das letzte Byte auf einen Wert setzen,
    # der definitiv nicht zum Rest-Padding passt.
    full_path = tmp_path / target_filename
    data = bytearray(full_path.read_bytes())

    # Wir setzen das letzte Byte des gesamten verschlüsselten Blocks auf 0x42 (beliebiger Wert)
    data[-1] = 0x11 # > 16
    full_path.write_bytes(data)

    # Jetzt muss die Library den Fehler werfen, weil 0x42 nicht zum Padding-Standard passt
    with pytest.raises(PKISecurityError):
        mgr.decrypt_password_file(target_filename, password="password123")


def test_decrypt_padding_length_error_lt1(tmp_path):
    # Triggert: pad_len < 1 or pad_len > 16
    mgr = PasswordManager(private_dir=tmp_path)
    # ... (Datei erstellen und verschlüsseln)
    input_file = tmp_path / "secret.txt"
    input_file.write_text("Test-Daten fuer Padding", encoding="utf-8")

    target_filename = "test.enc"
    mgr.encrypt_password_file(str(input_file), target_filename, password="password123")

    # Datei manipulieren: Das letzte Byte auf einen Wert setzen,
    # der definitiv nicht zum Rest-Padding passt.
    file_path = tmp_path / target_filename

    data = bytearray(file_path.read_bytes())
    data[-1] = 0x00  # Invalid: < 1
    file_path.write_bytes(data)
    with pytest.raises(PKISecurityError):
        mgr.decrypt_password_file("test.enc", password="password")

def test_decrypt_padding_content_error_missmage(tmp_path):
    # Triggert: padded_data[-pad_len:] != bytes([pad_len] * pad_len)
    mgr = PasswordManager(private_dir=tmp_path)
    # ... (Datei erstellen und verschlüsseln)
    input_file = tmp_path / "secret.txt"
    input_file.write_text("Test-Daten fuer Padding", encoding="utf-8")

    target_filename = "test.enc"
    mgr.encrypt_password_file(str(input_file), target_filename, password="password123")

    # Datei manipulieren: Das letzte Byte auf einen Wert setzen,
    # der definitiv nicht zum Rest-Padding passt.
    file_path = tmp_path / target_filename
    data = bytearray(file_path.read_bytes())
    # Wir setzen pad_len auf 2 (valide), manipulieren aber nur das letzte Byte,
    # sodass das Padding nicht mehr aus [0x02, 0x02] besteht.
    data[-1] = 0x02
    data[-2] = 0x99  # Ungültig: 0x99 != 0x02
    file_path.write_bytes(data)
    with pytest.raises(PKISecurityError):
        mgr.decrypt_password_file("test.enc", password="password")
