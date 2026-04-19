Get Started: PKI Exceptions
===========================

Dieses Modul definiert die zentrale Ausnahme-Hierarchie für die Bibliothek. 
Alle spezifischen Fehler leiten sich von der Basisklasse ``PKIError`` ab.


Basis-Ausnahme: PKIError
---------------------------

Jede Ausnahme in der Bibliothek ist ein ``PKIError``.

>>> from ftwpki.baselibs.exceptions import PKIError

>>> raise PKIError("Ein allgemeiner Fehler ist aufgetreten")
Traceback (most recent call last):
    ...
ftwpki.baselibs.exceptions.PKIError: Ein allgemeiner Fehler ist aufgetreten

>>> repr(PKIError())
'PKIError()'

Sicherheits-Ausnahme: PKISecurityError
-----------------------------------------

Wird bei allgemeineren kryptografischen Problemen verwendet. Sie erbt von ``PKIError``.

>>> from ftwpki.baselibs.exceptions import PKISecurityError

>>> raise PKISecurityError("Sicherheitsrelevanter Vorfall")
Traceback (most recent call last):
    ...
ftwpki.baselibs.exceptions.PKISecurityError: Sicherheitsrelevanter Vorfall

>>> isinstance(PKISecurityError(), PKIError)
True


>>> repr(PKISecurityError())
'PKISecurityError()'

Verschlüsselungs-Ausnahme: PKIEncryptionError
------------------------------------------------

Spezifischer Fehler für fehlgeschlagene Ver- oder Entschlüsselung. Erbt über 
die Sicherheits-Ebene.

>>> from ftwpki.baselibs.exceptions import PKIEncryptionError

>>> raise PKIEncryptionError("Falscher Schlüssel")
Traceback (most recent call last):
    ...
ftwpki.baselibs.exceptions.PKIEncryptionError: Falscher Schlüssel

>>> isinstance(PKIEncryptionError(), PKIError)
True

>>> isinstance(PKIEncryptionError(), PKISecurityError)
True


>>> repr(PKIEncryptionError())
'PKIEncryptionError()'

>>> from ftwpki.baselibs.exceptions import PKIValidationError

>>> pve=PKIValidationError(dut="OU", operation="MATCH", orig="IT")

>>> pve
PKIValidationError()

>>> raise pve
Traceback (most recent call last):
    ...
ftwpki.baselibs.exceptions.PKIValidationError: No match OU MATCH IT
