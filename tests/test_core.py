import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ftwpki.baselibs.core import load_private_key_from_pem  # Name anpassen


def test_load_key_wrong_type_raises_value_error():
    """
    Erzeugt einen EC-Key, um die RSA-Typ-Prüfung in Zeile 140 zu triggern.
    """
    # 1. Einen validen EC-Key generieren (nicht RSA!)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 2. Den EC-Key in die RSA-Ladefunktion füttern -> löst Zeile 140 aus
    with pytest.raises(ValueError, match="The provided key is not an RSA private key."):
        load_private_key_from_pem(ec_pem, passphrase="")
