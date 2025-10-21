# src/oracipher/crypto.py

import os
import base64
import logging
import hmac
import json
from pathlib import Path
from typing import Optional, Dict, Any

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
    """
    _SALT_SIZE: int = 16
    _KEY_LENGTH: int = 32
    _VERIFICATION_TOKEN: bytes = b"oracipher-verification-token-v1-argon2"

    # --- [修改] Argon2 参数被移至一个辅助方法中，以便于版本控制 ---
    @staticmethod
    def _get_current_argon2_params() -> Dict[str, int]:
        """Returns the current recommended Argon2 parameters."""
        return {
            "time_cost": 4,
            "memory_cost": 131072,  # 128 MB
            "parallelism": 2,
        }

    def __init__(self, data_dir: str):
        self._key: Optional[bytes] = None
        self._data_dir = Path(data_dir)
        self.salt_path: Path = self._data_dir / "salt.key"
        self.verification_path: Path = self._data_dir / "verification.key"
        self._data_dir.mkdir(parents=True, exist_ok=True)

    @property
    def is_unlocked(self) -> bool:
        return self._key is not None

    # --- [修改] _derive_key 签名更新以接受可变参数 ---
    @staticmethod
    def _derive_key(password: str, salt: bytes, argon2_params: Dict[str, int]) -> bytes:
        """
        Derives a URL-safe Base64 encoded encryption key using Argon2id.
        """
        logger.debug(f"Deriving encryption key using Argon2id with params: {argon2_params}")
        raw_key = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=argon2_params["time_cost"],
            memory_cost=argon2_params["memory_cost"],
            parallelism=argon2_params["parallelism"],
            hash_len=CryptoHandler._KEY_LENGTH,
            type=Type.ID,
        )
        return base64.urlsafe_b64encode(raw_key)

    # --- [修改] set_master_password 现在存储 KDF 参数 ---
    def set_master_password(self, password: str) -> None:
        """
        Sets the master password, storing KDF parameters for future use.
        """
        logger.info("Setting a new master password for the vault...")
        try:
            salt = os.urandom(self._SALT_SIZE)
            current_params = self._get_current_argon2_params()
            self._key = CryptoHandler._derive_key(password, salt, current_params)
            fernet = Fernet(self._key)

            self.salt_path.write_bytes(salt)

            encrypted_verification = fernet.encrypt(self._VERIFICATION_TOKEN)

            # 将参数和令牌打包成 JSON
            payload = {
                "params": current_params,
                "token": base64.b64encode(encrypted_verification).decode("utf-8"),
            }
            self.verification_path.write_bytes(json.dumps(payload, indent=2).encode("utf-8"))

            logger.info(
                "Master password set. Salt and versioned verification files created."
            )
        except IOError as e:
            logger.critical(f"Failed to write vault setup files: {e}", exc_info=True)
            raise OracipherError(f"Failed to write vault setup files: {e}") from e

    # --- [修改] unlock_with_master_password 现在读取 KDF 参数 ---
    def unlock_with_master_password(self, password: str) -> None:
        """
        Unlocks the vault by reading KDF parameters from the verification file.
        """
        try:
            salt = self.salt_path.read_bytes()
            
            # 解析 JSON payload
            payload_data = json.loads(self.verification_path.read_text("utf-8"))
            argon2_params = payload_data["params"]
            encrypted_verification = base64.b64decode(payload_data["token"])

            derived_key = CryptoHandler._derive_key(password, salt, argon2_params)
            fernet = Fernet(derived_key)
            decrypted_verification = fernet.decrypt(encrypted_verification, ttl=None)

            if hmac.compare_digest(decrypted_verification, self._VERIFICATION_TOKEN):
                self._key = derived_key
                logger.info("Vault unlocked successfully.")
            else:
                logger.error("Verification token mismatch after successful decryption.")
                raise CorruptDataError("Verification token mismatch.")

        except FileNotFoundError:
            raise VaultNotInitializedError("Vault files not found. Please set up the vault first.")
        except (json.JSONDecodeError, KeyError, base64.binascii.Error):
            logger.error("Verification file is corrupt or has an invalid format.")
            raise CorruptDataError("Verification file is corrupt.")
        except InvalidToken:
            raise IncorrectPasswordError("Incorrect master password.")
        except Exception as e:
            logger.error(f"An unexpected error occurred during unlock: {e}", exc_info=True)
            raise OracipherError(f"An unexpected error occurred during unlock: {e}") from e

    def lock(self) -> None:
        self._key = None
        logger.info("Vault has been locked. Encryption key cleared from memory.")

    # --- [修改] change_master_password 现在处理参数升级 ---
    def change_master_password(self, old_password: str, new_password: str) -> None:
        """
        Changes the master password, upgrading KDF parameters if necessary.
        """
        try:
            salt = self.salt_path.read_bytes()

            # 1. 使用存储的旧参数验证旧密码
            payload_data = json.loads(self.verification_path.read_text("utf-8"))
            old_argon2_params = payload_data["params"]
            old_encrypted_verification = base64.b64decode(payload_data["token"])

            old_derived_key = CryptoHandler._derive_key(old_password, salt, old_argon2_params)
            old_fernet = Fernet(old_derived_key)
            old_fernet.decrypt(old_encrypted_verification, ttl=None) # 验证旧密码
            logger.info("Old master password verified successfully.")

            # 2. 使用当前的新参数设置新密码
            new_params = self._get_current_argon2_params()
            new_derived_key = CryptoHandler._derive_key(new_password, salt, new_params)
            new_fernet = Fernet(new_derived_key)
            new_encrypted_verification = new_fernet.encrypt(self._VERIFICATION_TOKEN)

            # 3. 将新的参数和令牌写入文件
            new_payload = {
                "params": new_params,
                "token": base64.b64encode(new_encrypted_verification).decode("utf-8"),
            }
            self.verification_path.write_bytes(json.dumps(new_payload, indent=2).encode("utf-8"))

            self._key = new_derived_key
            logger.info("Master key changed. KDF parameters may have been upgraded.")

        except (InvalidToken, FileNotFoundError, json.JSONDecodeError, KeyError):
            raise IncorrectPasswordError("The provided 'old' master password was incorrect or files are corrupt.")
        except Exception as e:
            logger.error(f"An unknown error occurred while changing master password: {e}", exc_info=True)
            raise OracipherError(f"An unknown error occurred: {e}") from e

    def encrypt(self, data: str) -> str:
        # (无变化)
        if not self.is_unlocked:
            raise VaultLockedError("Cannot encrypt data: The vault is locked.")
        fernet = Fernet(self._key)
        return fernet.encrypt(data.encode("utf-8")).decode("utf-8")

    def decrypt(self, encrypted_data: str) -> str:
        # (无变化)
        if not self.is_unlocked:
            raise VaultLockedError("Cannot decrypt data: The vault is locked.")
        fernet = Fernet(self._key)
        try:
            return fernet.decrypt(encrypted_data.encode("utf-8"), ttl=None).decode("utf-8")
        except InvalidToken:
            raise CorruptDataError("Failed to decrypt data. It may be corrupt or the key is wrong.")

    def is_key_setup(self) -> bool:
        # (无变化)
        return self.salt_path.exists() and self.verification_path.exists()

    def get_salt(self) -> Optional[bytes]:
        # (无变化)
        if not self.is_key_setup():
            return None
        try:
            return self.salt_path.read_bytes()
        except IOError as e:
            logger.error(f"Could not read salt file: {e}", exc_info=True)
            return None