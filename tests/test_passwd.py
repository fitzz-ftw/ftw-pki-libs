import sys
from pathlib import Path

import pytest

from ftwpki.baselibs.exceptions import PKIEncryptionError, PKISecurityError

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
    # Da die Daten nun "Müll" sind, wird pad_len = padded_data[-1]
    # höchstwahrscheinlich > 16 sein -> Zeile 124 wird aktiv.
    with pytest.raises(PKISecurityError):
        mgr.decrypt_password_file("test.enc", password="falsches_passwort")

