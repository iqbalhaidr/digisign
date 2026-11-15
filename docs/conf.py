import os
import sys

sys.path.insert(0, os.path.abspath(".."))

project = "digisign"
author = "Muhammad Aufa Farabi, Joel Hotlan Haris Siahaan, Muhammad Iqbal Haidar"
copyright = "2026, " + author
release = "1.0.0"
version = release
language = "id"

extensions = [
    "sphinx.ext.autodoc", 
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "myst_parser",
]

source_suffix = {".rst": "restructuredtext", ".md": "markdown"}
exclude_patterns = ["_build", "requirements.txt"]

autodoc_member_order = "bysource"
autodoc_typehints = "signature"
autodoc_default_options = {
    "members": True,
    "show-inheritance": True,
}
add_module_names = False
python_use_unqualified_type_names = True

napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_use_rtype = False
napoleon_attr_annotations = True

myst_enable_extensions = ["colon_fence", "deflist", "fieldlist"]
myst_heading_anchors = 3

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "cryptography": ("https://cryptography.io/en/latest/", None),
}

html_theme = "furo"
html_title = f"digisign {release}"
html_static_path = []
html_theme_options = {
    "source_repository": "https://github.com/iqbalhaidr/digisign/",
    "source_branch": "main",
    "source_directory": "docs/",
}
