

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
ValidationResult(is_valid=True, errors=[])


>>> val_dn.validate(csr2)
ValidationResult(is_valid=False, errors=[ValidationError(field='C:de', message='MATCH', invalid_value='en')])

>>> val_dn.validate(csr3)
ValidationResult(is_valid=False, errors=[ValidationError(field='D', message='DISALLOWED', invalid_value='')])

>>> val_dn.validate(csr4)
ValidationResult(is_valid=True, errors=[])

True

>>> val_dn2= ValidatorDN(policy2, issuer)
>>> val_dn2
ValidatorDN({'C': 'match', 'B': 'supplied'})

>>> val_dn2.validate(csr1)
ValidationResult(is_valid=False, errors=[ValidationError(field='B', message='SUPPLIED', invalid_value='')])

>>> val_dn2.validate(csr5)
ValidationResult(is_valid=True, errors=[])

True

>>> val_dn3= ValidatorDN(policy3, issuer)
>>> val_dn3
ValidatorDN({'C': 'mach'})

>>> val_dn3.validate(csr1)
ValidationResult(is_valid=False, errors=[ValidationError(field='C', message='UNKNOWN_POLICY_MODE', invalid_value='mach')])


>>> from ftwpki.baselibs.validate import validate_uri

>>> validate_uri(None)
Warning: Could not process URI 'None': 'NoneType' object has no attribute 'split'
''

>>> from fitzzftw.develtool.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)
>>> crt_path = env.copy2cwd("test_short.crt.pem")
>>> from ftwpki.baselibs.core import (
...     load_certificate_from_pem,
... )

>>> cert_obj = load_certificate_from_pem(Path(crt_path).read_bytes())

>>> cert_obj
<Certificate(subject=<Name(C=DE,ST=,L=,O=Fitzz TeXnik Welt,OU=,CN=node-01.internal)>, ...)>

>>> from ftwpki.baselibs.validate import validate_and_clamp_validity

>>> validate_and_clamp_validity(cert_obj, 3650) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
ValidityDateCheckResult(not_after=datetime.datetime(...), 
    is_shortened=True, 
    original_requested_days=3650, 
    actual_days=...)

>>> validate_and_clamp_validity(cert_obj, 36) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
ValidityDateCheckResult(not_after=datetime.datetime(...), 
    is_shortened=False, 
    original_requested_days=36, 
    actual_days=36)

>>> env.clean_home()
>>> env.teardown()
