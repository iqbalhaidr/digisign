"""Hierarki exception yang dipakai seluruh modul.

Semua error yang disengaja diturunkan dari :class:`SignerError`, sehingga
lapisan subcommand cukup menangkap ``SignerError`` (dan ``OSError`` untuk I/O)
lalu memetakannya ke exit code.

.. code-block:: text

    Exception
    └── SignerError
        ├── FormatError
        ├── UnsupportedAlgorithmError
        └── InvalidKeyError
"""

class SignerError(Exception):
    "Default class untuk semua error pada program"

class FormatError(SignerError):
    "Class error untuk format tidak sesuai kontrak (struktur, tipe, ukuran, serialisasi)"

class UnsupportedAlgorithmError(SignerError):
    "Class error untuk nama profil algoritma yang tidak tersedia"

class InvalidKeyError(SignerError):
    "Class error untuk kunci dengan encoding PEM/DER, tipe, atau parameter yang tidak sesuai profil"
