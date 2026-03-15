"""pagevault - Password-protect regions of HTML files for static hosting."""

__version__ = "0.3.0"

from .crypto import PagevaultError, decrypt, encrypt, rewrap_keys
from .parser import lock_html, mark_body, mark_elements, unlock_html

# Backward-compatibility aliases
encrypt_html = lock_html
decrypt_html = unlock_html

__all__ = [
    "encrypt",
    "decrypt",
    "rewrap_keys",
    "PagevaultError",
    "lock_html",
    "unlock_html",
    "mark_elements",
    "mark_body",
    "encrypt_html",
    "decrypt_html",
    "__version__",
]
