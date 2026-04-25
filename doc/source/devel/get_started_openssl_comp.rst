


>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)
>>> index_file=env.copy2cwd("index.txt")

>>> from pprint import pprint

>>> from pathlib import Path
>>> from ftwpki.baselibs.openssl_comp import DbOpensslFile

>>> neue_db = DbOpensslFile(Path("neueDb.txt"))

>>> db = DbOpensslFile(Path("index.txt"))
>>> db
DbOpensslFile(DBFile: index.txt)

>>> db.get_revoked_records() #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
[CertificateRecord(status='R', 
    expiry=datetime.datetime(2026, 1, 1, 12, 0, tzinfo=datetime.timezone.utc), 
    revocation_date='260414201156Z,keyCompromise', 
    serial='03', 
    subject='CN=Leaked Key Server,O=FTW Projekte,C=DE', 
    filename='unknown'), 
 CertificateRecord(status='R', 
    expiry=datetime.datetime(2026, 3, 1, 12, 0, tzinfo=datetime.timezone.utc), 
    revocation_date='260414220000Z,superseded', 
    serial='04', 
    subject='CN=Old Global Policy,O=FTW Projekte,C=DE', 
    filename='unknown'), 
 CertificateRecord(status='R', 
    expiry=datetime.datetime(2026, 2, 1, 12, 0, tzinfo=datetime.timezone.utc), 
    revocation_date='260415100000Z,affiliationChanged', 
    serial='07', 
    subject='CN=Former Employee,O=FTW Projekte,C=DE', filename='unknown'), 
 CertificateRecord(status='R', 
    expiry=datetime.datetime(2025, 12, 1, 8, 0, tzinfo=datetime.timezone.utc), 
    revocation_date='260410080000Z,unspecified', 
    serial='09', 
    subject='CN=Unknown Reason,O=FTW Projekte,C=DE', 
    filename='unknown')]

>>> from ftwpki.baselibs.data import CertificateRecord
>>> import datetime

>>> record_revoked = CertificateRecord(
...     status='R',
...     expiry=datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.UTC),
...     revocation_date='260414201156Z,keyCompromise',
...     serial='0B',
...     subject='CN=Compromised,O=FTW Projekte,C=DE',
...     filename='unknown'
... )

>>> record_error = CertificateRecord(
...     status='V',
...     expiry=datetime.datetime(2027, 4, 14, 20, 11, 56, tzinfo=datetime.UTC),
...     revocation_date='',
...     serial='0A',
...     subject='CN=Server One,O=FTW Projekte,C=DE',
...     filename='unknown'
... )

>>> db.add_record(record_error)
Traceback (most recent call last):
    ...
ValueError: Serial 0A exists.

>>> db.add_record(record_revoked)

>>> len(db.get_revoked_records())
5

>>> db.find_active_by_subject(search_term="server") #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
[CertificateRecord(status='V', 
    expiry=datetime.datetime(2027, 1, 1, 12, 0, tzinfo=datetime.timezone.utc), 
    revocation_date='', 
    serial='02', 
    subject='CN=Server One,OU=IT,O=FTW Projekte,L=Frankfurt,ST=Hessen,C=DE', 
    filename='unknown'), 
 CertificateRecord(status='V', 
    expiry=datetime.datetime(2026, 12, 24, 18, 0, tzinfo=datetime.timezone.utc), 
    revocation_date='', 
    serial='0A', 
    subject='CN=Christmas Webserver,O=FTW Projekte,C=DE', 
    filename='unknown')]

>>> db.revoke_by_serial("0A", "keyCompromise" )

>>> len(db.get_revoked_records())
6

>>> db.revoke_by_serial("07")
Traceback (most recent call last):
    ...
ValueError: Zertifikat 07 ist bereits im Status R.

>>> db.revoke_by_serial("0F")
Traceback (most recent call last):
    ...
ValueError: Kein aktives Zertifikat mit Serial 0F gefunden.


>>> env.teardown()
