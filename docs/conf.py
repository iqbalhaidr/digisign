"""Konfigurasi Sphinx untuk dokumentasi API digisign."""

import os
import sys

# Root repositori agar autodoc dapat meng-import paket ``src``.
sys.path.insert(0, os.path.abspath(".."))

project = "digisign"
author = "Muhammad Aufa Farabi, Joel Hotlan Haris Siahaan, Muhammad Iqbal Haidar"
copyright = "2026, " + author
release = "1.0.0"
version = release
language = "id"

extensions = [
    "sphinx.ext.autodoc",       # ambil dokumentasi dari docstring
    "sphinx.ext.napoleon",      # dukungan docstring gaya Google (Args/Returns/Raises)
    "sphinx.ext.viewcode",      # tautan "[source]" ke kode sumber
    "sphinx.ext.intersphinx",   # tautan silang ke dokumentasi Python & cryptography
    "myst_parser",              # halaman naratif dalam Markdown
]

source_suffix = {".rst": "restructuredtext", ".md": "markdown"}
exclude_patterns = ["_build", "requirements.txt"]

# --- autodoc -----------------------------------------------------------------
autodoc_member_order = "bysource"
autodoc_typehints = "signature"
autodoc_default_options = {
    "members": True,
    "show-inheritance": True,
}
add_module_names = False
python_use_unqualified_type_names = True

# --- napoleon ----------------------------------------------------------------
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_use_rtype = False
napoleon_attr_annotations = True

# --- MyST --------------------------------------------------------------------
myst_enable_extensions = ["colon_fence", "deflist", "fieldlist"]
myst_heading_anchors = 3

# --- intersphinx -------------------------------------------------------------
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "cryptography": ("https://cryptography.io/en/latest/", None),
}

# --- HTML --------------------------------------------------------------------
html_theme = "furo"
html_title = f"digisign {release} — Dokumentasi API"
html_static_path = []
html_theme_options = {
    "source_repository": "https://github.com/iqbalhaidr/digisign/",
    "source_branch": "main",
    "source_directory": "docs/",
}
