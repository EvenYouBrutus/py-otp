"""
otp-text — One-Time Pad encryption for Unicode text.

Pure text in, pure text out. No files, no binary blobs.
"""

from .core import (
    generate_key,
    key_for,
    encrypt,
    decrypt,
    describe_key,
    symbols_to_text,
    text_to_symbols,
)

__version__ = "0.1.0"

__all__ = [
    "generate_key",
    "key_for",
    "encrypt",
    "decrypt",
    "describe_key",
    "symbols_to_text",
    "text_to_symbols",
    "__version__",
]