# src/oracipher/__init__.py

"""
Oracipher: A robust, standalone library for handling password vault
encryption, database management, and data format conversions.
"""

__version__ = "1.0.0"

# Import the main Vault class to make it directly accessible
from .vault import Vault

# Import the data format conversion functions
from . import data_formats

# Import the custom exceptions so users can catch them
from .exceptions import (
    OracipherError,
    IncorrectPasswordError,
    VaultNotInitializedError,
    VaultLockedError,
    CorruptDataError,
    InvalidFileFormatError,
)

# Explicitly define what is exposed to the user when they do `from oracipher import *`
__all__ = [
    "Vault",
    "data_formats",
    "OracipherError",
    "IncorrectPasswordError",
    "VaultNotInitializedError",
    "VaultLockedError",
    "CorruptDataError",
    "InvalidFileFormatError",
]