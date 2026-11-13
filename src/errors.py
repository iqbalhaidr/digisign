class SignerError(Exception):
    "Default class untuk semua error pada program"

class FormatError(SignerError):
    "Class error untuk format tidak sesuai kontrak (struktur, tipe, ukuran, serialisasi)"