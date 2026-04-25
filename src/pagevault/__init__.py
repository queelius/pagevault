"""pagevault - Password-protect regions of HTML files for static hosting."""

__version__ = "0.4.1"

from .crypto import PagevaultError
from .parser import lock_html, mark_body, mark_elements, unlock_html

__all__ = [
    "PagevaultError",
    "lock_html",
    "unlock_html",
    "mark_elements",
    "mark_body",
    "__version__",
]
