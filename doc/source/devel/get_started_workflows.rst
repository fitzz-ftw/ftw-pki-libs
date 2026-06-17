The Certificat Sign Request Creation
#########################################




.. SECTION - Setup

>>> from fitzzftw.devtools.testinfra import TestHomeEnvironment
>>> from pathlib import Path
>>> env = TestHomeEnvironment(Path("doc/source/devel/testhome"),
...     appname="ftwpki", appauthor="FitzzTeXnikWelt")
>>> env.setup(True)
>>> env.clean_home()

.. !SECTION
.. SECTION - Prepare

>>> from pathlib import Path

>>> import getpass

>>> conf_file = env.copy2cwd("test_workflows/csr_user_conf.toml","csr_user_conf.toml")

>>> def getpasswd(prompt:str)->str:
...     print(prompt)
...     return "strenggeheim"

>>> cmd_line="--conf-file csr_user_conf.toml  "
>>> cmd_line += " -k tim"
>>> cmd_line += " -dns www.secure.example.org"
>>> cmd_line += " www-admin@example.org"

>>> import shlex
>>> sys_argv= shlex.split(cmd_line) 
>>> sys_argv #doctest: +NORMALIZE_WHITESPACE
['--conf-file', 
    'csr_user_conf.toml',
     '-k', 'tim',
    '-dns', 'www.secure.example.org',
    'www-admin@example.org']



.. !SECTION

.. SECTION - Start programm

>>> from ftwpki.baselibs.workflows import CSRWorkflow
>>> csr_creator = CSRWorkflow()

.. SECTION - Configuration

>>> csr_creator.configuration(sys_argv)


.. !SECTION - Configuration

>>> csr_creator.policy
UserPolicy()

>>> csr_creator.mandantory_san
True


.. SECTION - CSR Creation

>>> csr_creator.csr_creation()

.. !SECTION - CSR Creation

.. SECTION - Password Input

Simulating User Input
----------------------

The :class:`~securify.input.password.PasswordDoubleCheck` class is designed for 
interactive use. 
To demonstrate its behavior in a non-interactive environment like this 
documentation, we use a helper class called :class:`StubPassword`.

This stub acts as a "script" for our tests:

* **State Management:**
  It uses a Python generator to remember which password to return next.

* **Timing Simulation:** 
  It uses :external+python:func:`time.sleep` to simulate the time a human needs to 
  type. This allows us to test security features like the minimum delay.
* **Visibility:** 
  It prints the prompt strings so you can see exactly when the application 
  asks for input.


>>> import time
>>> class StubPassword:
...     def __init__(self):
...         self.generate = self._generate()
...     def _generate(self):
...         # first run
...         yield "secret"
...         time.sleep(2)
...         yield "secret"
...     def __call__(self, prompt):
...         print(prompt, flush=True)
...         return next(self.generate)
...     def reset(self):
...         self.generate = self._generate()

>>> getpass.getpass= StubPassword()


.. note::
   
   In automated environments (like GitHub Actions), there is no interactive terminal (TTY) available. 
   To prevent the CI process from failing with a ``PasswordTerminalError``, we must explicitly 
   set ``require_terminal=False``.

   **The error you would otherwise see in the CI logs:**

   .. code-block:: text

      154 >>> checkpw()
      Differences (unified diff with -expected +actual):
          @@ -1,3 +1,12 @@
           Traceback (most recent call last):
          -    ...
          -securify.input.exceptions.PasswordSpeedError: Input rejected: Entry was too fast (0.00s). Minimum required: 1.5s.
          +  File "/opt/hostedtoolcache/Python/3.13.13/x64/lib/python3.13/doctest.py", line 1398, in __run
          +    exec(compile(example.source, filename, "single",
          +    ~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
          +                 compileflags, True), test.globs)
          +                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
          +  File "<doctest get_started_password.rst[25]>", line 1, in <module>
          +    checkpw()
          +    ~~~~~~~^^
          +  File "/home/runner/work/securify/securify/.tox/py313/lib/python3.13/site-packages/securify/input/password.py", line 172, in __call__
          +    raise PasswordTerminalError("Operation rejected: Input is not a terminal (TTY).")
          +securify.input.exceptions.PasswordTerminalError: Operation rejected: Input is not a terminal (TTY).
      
      /home/runner/work/securify/securify/doc/source/devel/get_started_password.rst:154: DocTestFailure


>>> csr_creator.create_password()
Enter password: 
Retype password: 

.. !SECTION - Password Input

.. SECTION - Keypair Creation

>>> csr_creator.key_pair_creation()

.. !SECTION - Keypair Creation

.. SECTION - Save Keys

>>> csr_creator.save_keys()

.. !SECTION - Save Keys
.. SECTION - Save CSR

>>> csr_creator.save_csr()

.. !SECTION - Save CSR
.. SECTION - pki- Container

>>> csr_creator.process_pki_container()

.. !SECTION - pki- Container

.. SECTION - Cleanup

>>> csr_creator.cleanup()

.. !SECTION - Cleanup

.. !SECTION - Stop programm

.. SECTION - Test existing keys

>>> conf_path:Path = env.config_dir
>>> public_path:Path = env.data_dir



>>> (conf_path / ".private"/ "tim.key.pem").is_file()
True

>>> (public_path / "csr_user_conf.pki").is_file()
True


.. !SECTION - Test existing keys

.. SECTION - Load and read CSR

>>> from ftwpki.baselibs.core import load_csr_from_pem

>>> csr_obj = load_csr_from_pem(Path("csr_user_conf.csr").read_bytes()) 

>>> csr_obj #doctest: +ELLIPSIS
<cryptography.hazmat.bindings._rust.x509.CertificateSigningRequest object at ...>

>>> from ftwpki.baselibs.core import get_subject_dict

>>> get_subject_dict(csr_obj) #doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
{'countryName': 'DE', 
 'stateOrProvinceName': '', 
 'localityName': 'Somewherecity', 
 'organizationName': 'Fitzz TeXnik Welt', 
 'organizationalUnitName': 'IT-Security', 
 'commonName': 'IT-Security Server'}

.. !SECTION - Load and read CSR

>>> mistakes = CSRWorkflow()

>>> mistakes.save_csr()
Traceback (most recent call last):
    ...
RuntimeError: Has no CSR initialized.
Run 'csr_creation()' before.

>>> cmd_line = " -k tim"
>>> cmd_line += " -dns www.secure.example.org"
>>> cmd_line += " www-admin@example.org"

>>> sys_argv= shlex.split(cmd_line) 

>>> mistakes.configuration(sys_argv)
Traceback (most recent call last):
    ...
argparse.ArgumentError: the following arguments are required: --conf-file

>>> from ftwpki.baselibs.policies import ServerPolicy

>>> mistakes.policy = ServerPolicy()

>>> mistakes.policy
ServerPolicy()

>>> mistakes.mandantory_san = False

.. SECTION - Teardown

>>> env.clean_home()
>>> env.teardown()

.. !SECTION - Teardown
