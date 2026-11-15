"""Exception hierarchy shared by all modules.

All intentional errors derive from :class:`SignerError`, so subcommands only
need to catch ``SignerError`` (and ``OSError`` for I/O) and map it to an exit
code.

.. code-block:: text

    Exception
    └── SignerError
        ├── FormatError
        ├── UnsupportedAlgorithmError
        └── InvalidKeyError
"""

class SignerError(Exception):
    "Base class for all program errors."

class FormatError(SignerError):
    "Data violates the format contract (structure, type, size, serialization)."

class UnsupportedAlgorithmError(SignerError):
    "Unknown algorithm profile name."

class InvalidKeyError(SignerError):
    "Key has invalid PEM/DER encoding, type, or parameters for its profile."
