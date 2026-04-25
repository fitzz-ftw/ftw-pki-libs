Get started passwd
===================

>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"))
>>> env.setup(True)


>>> from ftwpki.baselibs.passwd import PasswordManager
>>> pm = PasswordManager(private_dir="./test_private")
>>> pm
PasswordManager(private_dir='test_private')

>> p = Path("test_pass.txt")
>> p.write_bytes(b"MeineSicherePassphrase123  \n\x00")
29

>>> test_pass = env.copy2cwd("test_pass.txt")

>>> pm.encrypt_password_file(test_pass, "root.enc", "my_password")
>>> decrypted = pm.decrypt_password_file("root.enc", "my_password")
>>> decrypted
'MeineSicherePassphrase123'


>>> pm_enc_stat= (pm.private_dir / "root.enc").stat().st_mode

>>> import stat

>>> stat.filemode(pm_enc_stat)
'-rw-------'

>>> from ftwpki.baselibs.passwd import PasswordCli

>>> pc = PasswordCli()
>>> pc
PasswordCli()

>>> pm.encrypt_password_file("not_exist_pw.txt", "root.enc", "my_password")
Traceback (most recent call last):
    ...
FileNotFoundError: Input file not_exist_pw.txt is missing or empty.

>>> pm.decrypt_password_file("not_exist_root.enc", "my_password")
Traceback (most recent call last):
    ...
FileNotFoundError: Encrypted file not_exist_root.enc not found.

>>> from ftwpki.baselibs.passwd import get_parser
>>> get_parser() # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
ArgumentParser(prog=..., 
    usage=None, 
    description='Encrypt a passphrase file into the private directory.', 
    formatter_class=<class 'argparse.HelpFormatter'>, 
    conflict_handler='error', 
    add_help=True)

>>> env.teardown()
