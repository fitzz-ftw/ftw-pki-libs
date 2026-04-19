

>>> from datetime import datetime

>>> from ftwpki.baselibs.data import CertificateRecord

>>> cr = CertificateRecord(status= "V", 
...    expiry= datetime.now(),
...    revocation_date="",
...    serial="0x20",
...    subject="test")

>>> cr # doctest: +NORMALIZE_WHITESPACE +ELLIPSIS
CertificateRecord(status='V', 
    expiry=datetime.datetime(...), 
    revocation_date='', 
    serial='0x20', 
    subject='test', 
    filename='unknown')

>>> cr.openssl_index_line # doctest: +ELLIPSIS 
'V\t...\t\t0x20\tunknown\ttest'

>>> print(cr.openssl_index_line) # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
V   ...           0x20    unknown test

>>> from ftwpki.baselibs.data import ValidationError

>>> val_error = ValidationError(field="CN",
...     message="Does not 'MATCH'!",
...     invalid_value="Wrong value")

>>> val_error
ValidationError(field='CN', message="Does not 'MATCH'!", invalid_value='Wrong value')

>>> print(val_error)
  - [CN]: Does not 'MATCH'! (Got: 'Wrong value')
