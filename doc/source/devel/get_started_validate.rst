

>>> policy={"C": "match", "A":"optional"}
>>> policy2={"C": "match","B":"supplied"}
>>> policy3={"C": "mach"}
>>> issuer={"C": "de"}
>>> csr1={"C":"de"}
>>> csr2={"C":"en"}
>>> csr3={"C":"de","D":"en"}
>>> csr4={"C":"de","D":""}
>>> csr5={"C":"de", "B":"OK"}


>>> from ftwpki.baselibs.validate import ValidatorDN

>>> val_dn= ValidatorDN(policy, issuer)
>>> val_dn
ValidatorDN({'C': 'match', 'A': 'optional'})

>>> val_dn.validate(csr1)
True

>>> val_dn.validate(csr2)
Traceback (most recent call last):
    ...
ftwpki.baselibs.exceptions.PKIValidationError: No match C:en MATCH de

>>> val_dn.validate(csr3)
Traceback (most recent call last):
    ...
ftwpki.baselibs.exceptions.PKIValidationError: No match D DISALLOWED empty

>>> val_dn.validate(csr4)
True

>>> val_dn2= ValidatorDN(policy2, issuer)
>>> val_dn2
ValidatorDN({'C': 'match', 'B': 'supplied'})

>>> val_dn2.validate(csr1)
Traceback (most recent call last):
    ...
ftwpki.baselibs.exceptions.PKIValidationError: No match B SUPPLIED any_value

>>> val_dn2.validate(csr5)
True

>>> val_dn3= ValidatorDN(policy3, issuer)
>>> val_dn3
ValidatorDN({'C': 'mach'})

>>> val_dn3.validate(csr1)
Traceback (most recent call last):
    ...
ftwpki.baselibs.exceptions.PKIValidationError: No match C UNKNOWN_POLICY_MODE defined mode: mach
