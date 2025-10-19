# src/oracipher/crypto.py

import os
import base64
import logging
import hmac  # [新增] 导入 hmac 模块用于安全比较
from pathlib import Path  # [新增] 导入 pathlib 用于现代化的路径处理
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from argon2.low_level import hash_secret_raw, Type

from .exceptions import (
    IncorrectPasswordError,
    VaultNotInitializedError,
    VaultLockedError,
    CorruptDataError,
    OracipherError,
)

logger = logging.getLogger(__name__)


class CryptoHandler:
    """
    Manages all core cryptographic operations including key derivation,
    encryption, and decryption for the vault.

    This class encapsulates the security primitives:
    - Key Derivation: Argon2id is used to derive a strong encryption key
      from a user's master password.
    - Symmetric Encryption: Fernet (AES-128-CBC with HMAC-SHA256) is used
      for authenticated encryption, ensuring confidentiality and integrity.
    """

    _SALT_SIZE: int = 16
    _ARGON2_TIME_COST: int = 4
    _ARGON2_MEMORY_COST: int = 131072  # 128 MB
    _ARGON2_PARALLELISM: int = 2
    _KEY_LENGTH: int = 32
    _VERIFICATION_TOKEN: bytes = b"oracipher-verification-token-v1-argon2"

    def __init__(self, data_dir: str):
        """
        Initializes the CryptoHandler.

        Args:
            data_dir: Path to the application data directory where salt and
                      verification files are stored.
        """
        self._key: Optional[bytes] = None
        # [修改] 使用 pathlib 进行路径管理
        self._data_dir = Path(data_dir)
        self.salt_path: Path = self._data_dir / "salt.key"
        self.verification_path: Path = self._data_dir / "verification.key"
        self._data_dir.mkdir(parents=True, exist_ok=True)

    @property
    def is_unlocked(self) -> bool:
        """Check if the encryption key is currently loaded in memory."""
        return self._key is not None

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """
        Derives a URL-safe Base64 encoded encryption key from a master password and salt
        using Argon2id.
        """
        logger.debug("Deriving encryption key using Argon2id...")
        raw_key = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=CryptoHandler._ARGON2_TIME_COST,
            memory_cost=CryptoHandler._ARGON2_MEMORY_COST,
            parallelism=CryptoHandler._ARGON2_PARALLELISM,
            hash_len=CryptoHandler._KEY_LENGTH,
            type=Type.ID,
        )
        return base64.urlsafe_b64encode(raw_key)

    def set_master_password(self, password: str) -> None:
        """
        Sets the master password for the first time.

        Generates a new salt, derives a key, encrypts a verification token,
        and stores both the salt and the encrypted token.

        Raises:
            OracipherError: If there's an I/O error writing the setup files.
        """
        logger.info("Setting a new master password for the vault...")
        try:
            salt = os.urandom(self._SALT_SIZE)
            self._key = CryptoHandler._derive_key(password, salt)
            fernet = Fernet(self._key)

            self.salt_path.write_bytes(salt)

            encrypted_verification = fernet.encrypt(self._VERIFICATION_TOKEN)
            self.verification_path.write_bytes(encrypted_verification)

            logger.info(
                "Master password set successfully. Salt and verification files created."
            )
        except IOError as e:
            logger.critical(f"Failed to write vault setup files: {e}", exc_info=True)
            raise OracipherError(f"Failed to write vault setup files: {e}") from e

    def unlock_with_master_password(self, password: str) -> None:
        """
        Attempts to unlock the vault with the given master password.

        On success, the derived key is loaded into memory for subsequent operations.
        On failure, a specific exception is raised.

        Raises:
            VaultNotInitializedError: If the salt or verification file is not found.
            IncorrectPasswordError: If the password is wrong and decryption fails.
            OracipherError: For other unexpected errors.
        """
        try:
            salt = self.salt_path.read_bytes()
            derived_key = CryptoHandler._derive_key(password, salt)
            fernet = Fernet(derived_key)
            encrypted_verification = self.verification_path.read_bytes()
            decrypted_verification = fernet.decrypt(encrypted_verification, ttl=None)

            # [高优先级安全修复] 使用 hmac.compare_digest 进行常量时间比较，防止时序攻击
            if hmac.compare_digest(decrypted_verification, self._VERIFICATION_TOKEN):
                self._key = derived_key
                logger.info("Vault unlocked successfully.")
            else:
                # This case is highly unlikely but indicates file corruption.
                logger.error("Verification token mismatch after successful decryption.")
                raise CorruptDataError("Verification token mismatch.")

        except FileNotFoundError:
            logger.error(
                "Salt or verification file not found. Vault may not be initialized."
            )
            raise VaultNotInitializedError(
                "Vault files not found. Please set up the vault first."
            )
        except InvalidToken:
            logger.warning(
                "Incorrect master password (failed to decrypt verification token)."
            )
            raise IncorrectPasswordError("Incorrect master password.")
        except Exception as e:
            logger.error(
                f"An unexpected error occurred during unlock: {e}", exc_info=True
            )
            raise OracipherError(
                f"An unexpected error occurred during unlock: {e}"
            ) from e

    def lock(self) -> None:
        """
        Locks the vault by clearing the encryption key from memory.
        """
        self._key = None
        logger.info("Vault has been locked. Encryption key cleared from memory.")

    def change_master_password(self, old_password: str, new_password: str) -> None:
        """
        Changes the master password.

        Verifies the old password, then re-encrypts the verification file with a new key
        derived from the new password. The session key is updated.
        """
        try:
            salt = self.salt_path.read_bytes()

            # Verify old password
            old_derived_key = CryptoHandler._derive_key(old_password, salt)
            old_fernet = Fernet(old_derived_key)
            encrypted_verification = self.verification_path.read_bytes()
            
            # Decrypt will internally check HMAC, which is safe. No explicit compare needed here.
            old_fernet.decrypt(encrypted_verification, ttl=None)
            logger.info("Old master password verified successfully.")

            # Set new password
            new_derived_key = CryptoHandler._derive_key(new_password, salt)
            new_fernet = Fernet(new_derived_key)
            new_encrypted_verification = new_fernet.encrypt(self._VERIFICATION_TOKEN)
            self.verification_path.write_bytes(new_encrypted_verification)

            self._key = new_derived_key
            logger.info("Master key has been successfully changed at the crypto layer.")

        except (InvalidToken, FileNotFoundError):
            logger.warning(
                "The provided 'old' master password was incorrect during change attempt."
            )
            raise IncorrectPasswordError(
                "The provided 'old' master password was incorrect."
            )
        except Exception as e:
            logger.error(
                f"An unknown error occurred while changing master password: {e}",
                exc_info=True,
            )
            raise OracipherError(
                f"An unknown error occurred while changing master password: {e}"
            ) from e

    def encrypt(self, data: str) -> str:
        """
        Encrypts string data using the currently loaded session key.
        """
        if not self.is_unlocked:
            raise VaultLockedError("Cannot encrypt data: The vault is locked.")

        # self._key is guaranteed to be bytes if unlocked
        fernet = Fernet(self._key)  # type: ignore
        return fernet.encrypt(data.encode("utf-8")).decode("utf-8")

    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypts string data using the currently loaded session key.
        """
        if not self.is_unlocked:
            raise VaultLockedError("Cannot decrypt data: The vault is locked.")

        # self._key is guaranteed to be bytes if unlocked
        fernet = Fernet(self._key)  # type: ignore
        try:
            return fernet.decrypt(encrypted_data.encode("utf-8"), ttl=None).decode(
                "utf-8"
            )
        except InvalidToken:
            raise CorruptDataError(
                "Failed to decrypt data. It may be corrupt or the key is wrong."
            )

    def is_key_setup(self) -> bool:
        """Checks if the vault has been initialized."""
        return self.salt_path.exists() and self.verification_path.exists()

    def get_salt(self) -> Optional[bytes]:
        """Safely reads and returns the salt file content."""
        if not self.is_key_setup():
            return None
        try:
            return self.salt_path.read_bytes()
        except IOError as e:
            logger.error(f"Could not read salt file: {e}", exc_info=True)
            return None