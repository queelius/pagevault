"""pagevault - Password-protect regions of HTML files for static hosting."""

__version__ = "0.3.2"

from .crypto import PagevaultError
from .parser import lock_html, mark_body, mark_elements, unlock_html

# Backward-compatibility aliases for pre-v0.4.0 API names
encrypt_html = lock_html
decrypt_html = unlock_html

__all__ = [
    "PagevaultError",
    "lock_html",
    "unlock_html",
    "mark_elements",
    "mark_body",
    "encrypt_html",
    "decrypt_html",
    "__version__",
]
