# File: src/ftwpki/baselibs/utils.py
# Author: Fitzz TeXnik Welt
# Email: FitzzTeXnikWelt@t-online.de
# License: LGPLv2 or above
"""
utils
===============================


Modul utils documentation
"""

from pathlib import Path

from cryptography import x509


def assert_is_pem_cert(data: bytes, name: str="Unknown") -> None:
    """
    Interner Gatekeeper: Prüft ein einzelnes Byte-Objekt auf Herz und Nieren.
    """
    
    if not isinstance(data, bytes):
        raise TypeError(f"'{name}' muss vom Typ 'bytes' sein, nicht {type(data).__name__}.")

    try:
        # Der ultimative Test von cryptography
        x509.load_pem_x509_certificate(data.strip())
    except Exception as e:
        raise ValueError(f"'{name}' ist kein gültiges PEM-Zertifikat: {e}")

# def validate_and_format_chain(*chain_parts: bytes) -> bytes:
#     validated:list[bytes]=[]
#     for i, part in enumerate(chain_parts,1):
#         assert_is_pem_cert(part.strip(), f"Chainpart {i}")
#         validated.append(part.strip())
#     return b"\n".join(validated)

# def encrypt_bytedata(unencrypted_data, recipient_cert):
#     """
#     Erstellt ein S/MIME Paket, das mit 'openssl smime -decrypt -binary'
#     kompatibel ist.
#     """
#     options = [pkcs7.PKCS7Options.Binary]  # Wichtig für ZIP-Dateien!

#     builder = pkcs7.PKCS7EnvelopeBuilder().set_data(unencrypted_data)
#     builder = builder.add_recipient(recipient_cert)

#     # Wir nutzen SMIME-Encoding, damit die Header für OpenSSL da sind
#     return builder.encrypt(Encoding.SMIME, options)


# def decrypt_bytedata(
#     encrypted_data: bytes, 
#     recipient_key: RSAPrivateKey, 
#     recipient_cert: x509.Certificate
# ) -> bytes:
#     """
#     Entschlüsselt das S/MIME-Paket und gibt die rohen ZIP-Bytes zurück.
#     Nutzt die native cryptography (v44+) Implementierung.
#     """
#     # 1. Zertifikat und Key laden (Gatekeeper-Style)
#     # cert = x509.load_pem_x509_certificate(recipient_cert)
#     # key = recipient_key #serialization.load_pem_private_key(recipient_key_pem, password=None)

#     # 2. Entschlüsseln
#     # Leere options [] erlauben Binary-Daten (unser ZIP)
#     options = []

#     try:
#         decrypted_data = pkcs7.pkcs7_decrypt_smime(encrypted_data, 
#                                                    recipient_cert, 
#                                                    recipient_key, 
#                                                    options)
#         return decrypted_data
#     except Exception as e:
#         raise ValueError(f"Entschlüsselung fehlgeschlagen: {e}")

def format_extension(ext, indent:int=0):
    val = ext.value
    name = ext.oid._name
    inden:str = " "*4*indent

    if isinstance(val, x509.BasicConstraints):
        return (
            f"{inden}{name}:\n{inden*2} CA={'Yes' if val.ca else 'No'}, "
            f"path_length={val.path_length}"
        )

    if isinstance(val, x509.KeyUsage):
        # Wir definieren die Liste explizit, um die ValueError-Falle zu umgehen
        potential_usages = [
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
        ]

        # Sonderbehandlung für die "Agreement"-Abhängigkeiten
        if val.key_agreement:
            potential_usages.extend(["encipher_only", "decipher_only"])

        usages = [attr for attr in potential_usages if getattr(val, attr)]
        used = ", ".join(usages)
        return f"{inden}{name}:\n{inden * 2} {used}"



    if hasattr(val,"_usages"):
        ret_val = ", ".join([item._name for item in val._usages])
        return f"{inden}{name}:\n{inden * 2} {ret_val}"

    if name=="authorityKeyIdentifier":
        return f"{inden}{name}:\n{inden * 2} {val.key_identifier}"

    if hasattr(val, "_descriptions"):
        ret_val = f"\n{inden*2} ".join(
            [
                ": ".join((use.access_method._name, use.access_location.value))
                for use in val._descriptions
            ]
        )
        return f"{inden}{name}:\n{inden * 2} {ret_val}"
        

    if name == "cRLDistributionPoints":
        ret_val = f"\n{inden * 2}".join(
            [item.value for use in val._distribution_points for item in use.full_name]
        )
        return f"{inden}{name}:\n{inden * 2} {ret_val}"
        
    if name== "subjectKeyIdentifier":
        return f"{inden}{name}:\n{inden * 2} {val.digest}"

    return f"{name}: {val}"

def get_cert_text(pem_path: str) -> str:
    """
    Gibt die menschenlesbare Zusammenfassung des Zertifikats zurück.
    Ersetzt den Aufruf von 'openssl x509 -text'.
    """
    cert_bytes = Path(pem_path).read_bytes()
    cert = x509.load_pem_x509_certificate(cert_bytes)

    lines = [
        f"Subject:\n\t {cert.subject.rfc4514_string()}",
        f"Issuer:\n\t {cert.issuer.rfc4514_string()}",
        f"Serial Number:\n\t {cert.serial_number}",
        f"Not Before:\n\t {cert.not_valid_before_utc}",
        f"Not After:\n\t {cert.not_valid_after_utc}",
        f"Version:\n\t {cert.version.name}",
    ]

    # Extensions hinzufügen (ähnlich wie OpenSSL)
    lines.append("Extensions:")
    for ext in cert.extensions:
        # lines.append(f"    {ext.oid._name}: {ext.value}")
        lines.append(format_extension(ext, indent=1))

    return "\n".join(lines)

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
    test_file = testfiles_dir / "get_started_utils.rst"
    
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
