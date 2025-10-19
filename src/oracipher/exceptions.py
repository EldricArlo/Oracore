# src/oracipher/exceptions.py

"""
Defines the custom exceptions used throughout the oracipher library.

This allows users of the library to write specific `try...except` blocks for
predictable error conditions, leading to more robust application code.
"""

class OracipherError(Exception):
    """
    Base exception for all errors raised by the oracipher library.
    
    Catching this exception will catch any error originating from this library,
    allowing for generic library-specific error handling.
    """
    pass


class IncorrectPasswordError(OracipherError):
    """
    Raised when an incorrect password is provided for an operation that
    requires password verification.
    
    This typically occurs during `vault.unlock()` or `vault.change_master_password()`.
    """
    pass


class VaultNotInitializedError(OracipherError):
    """
    Raised when an operation is attempted on a vault that has not yet been
    set up (i.e., no master password has been set).
    """
    pass


class VaultLockedError(OracipherError):
    """
    Raised when an encryption, decryption, or data access operation is
    attempted while the vault is in a locked state.
    
    The vault must be successfully unlocked with `vault.unlock()` before these
    operations can be performed.
    """
    pass


class CorruptDataError(OracipherError):
    """
    Raised when encrypted data appears to be corrupt, has been tampered with,
    or cannot be authenticated by the underlying cryptography layer (e.g., HMAC check fails).
    
    This can also be raised during unlock if the verification token is found to be invalid
    after a successful decryption step, indicating file corruption.
    """
    pass


class InvalidFileFormatError(OracipherError):
    """
    Raised when attempting to import data from a file that does not match the
    expected format for the specified parser.
    
    This can be due to incorrect headers in a CSV file, malformed JSON, or
    decryption failure of an encrypted import format like .skey or .spass.
    """
    pass