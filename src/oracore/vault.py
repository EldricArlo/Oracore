# src/oracipher/vault.py

import os
import shutil
import logging
import json
import base64
from pathlib import Path
from typing import List, Dict, Any, Optional, Iterator

from .crypto import CryptoHandler
from ._internal_db import DataManager
from .exceptions import (
    VaultLockedError, 
    OracipherError, 
    VaultNotInitializedError, 
    InvalidFileFormatError,
    IncorrectPasswordError
)
from ._internal_migration import check_and_migrate_schema
from cryptography.fernet import Fernet


logger = logging.getLogger(__name__)

def _secure_delete(path: Path, passes: int = 1):
    # (无变化)
    try:
        if not path.is_file():
            return
        
        file_size = path.stat().st_size
        if file_size == 0:
            path.unlink()
            return
        
        with open(path, "rb+") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(file_size))
        path.unlink()
        logger.debug(f"Securely deleted file: {path}")
    except (IOError, OSError) as e:
        logger.warning(f"Could not securely delete file {path}: {e}", exc_info=True)


class Vault:
    """
    The main entry point for interacting with an oracipher vault.

    This class provides a high-level API that encapsulates all cryptographic
    and database operations, presenting a simple and secure interface.

    .. note:: An instance of the Vault class is NOT thread-safe. For use in
              multi-threaded applications, create a separate Vault instance
              per thread.
    """

    def __init__(self, data_dir: str):
        self._data_dir = Path(data_dir)
        self.db_path = self._data_dir / "safekey.db"

        check_and_migrate_schema(str(self.db_path))

        self._crypto = CryptoHandler(str(self._data_dir))
        self._db = DataManager(str(self.db_path), self._crypto)

    @property
    def is_setup(self) -> bool:
        return self._crypto.is_key_setup()

    @property
    def is_unlocked(self) -> bool:
        return self._crypto.is_unlocked

    # --- [修改] 添加密码最小长度检查 ---
    def setup(self, master_password: str, min_length: int = 12) -> None:
        """
        Sets up the vault for the first time with a master password.
        
        Args:
            master_password: The chosen master password.
            min_length: The minimum required password length. Set to 0 to disable.
        
        Raises:
            ValueError: If the master password is shorter than min_length.
        """
        if self.is_setup:
            raise OracipherError("Vault is already initialized.")
        if min_length > 0 and len(master_password) < min_length:
            raise ValueError(f"Master password must be at least {min_length} characters long.")
            
        self._crypto.set_master_password(master_password)
        self._db.connect()

    def unlock(self, master_password: str) -> None:
        # (无变化)
        if not self.is_setup:
            raise VaultNotInitializedError(
                "Vault has not been set up. Please call setup() first."
            )
        self._crypto.unlock_with_master_password(master_password)
        if self.is_unlocked:
            self._db.connect()

    def lock(self) -> None:
        # (无变化)
        self._crypto.lock()
        self._db.close()

    def get_all_entries(self) -> List[Dict[str, Any]]:
        # (无变化)
        if not self.is_unlocked:
            raise VaultLockedError("Vault must be unlocked to retrieve entries.")
        return self._db.get_all_entries()

    def get_all_entries_iter(self) -> Iterator[Dict[str, Any]]:
        # (无变化)
        if not self.is_unlocked:
            raise VaultLockedError("Vault must be unlocked to retrieve entries.")
        yield from self._db.get_all_entries_iter()

    def save_entry(self, entry_data: Dict[str, Any]) -> int:
        # (无变化)
        if not self.is_unlocked:
            raise VaultLockedError("Vault must be unlocked to save an entry.")
        return self._db.save_entry(entry_data)
    
    def delete_entry(self, entry_id: int) -> None:
        # (无变化)
        if not self.is_unlocked:
            raise VaultLockedError("Vault must be unlocked to delete an entry.")
        self._db.delete_entry(entry_id)

    # --- [修改] 添加对新密码的最小长度检查 ---
    def change_master_password(
        self, old_password: str, new_password: str, min_length: int = 12
    ) -> None:
        """
        Changes the master password for the vault.
        
        Args:
            old_password: The current master password.
            new_password: The new master password.
            min_length: The minimum required length for the new password.
        
        Raises:
            ValueError: If the new password is shorter than min_length.
            IncorrectPasswordError: If the old password is not correct.
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault must be unlocked to change the master password.")
        
        if min_length > 0 and len(new_password) < min_length:
            raise ValueError(f"New master password must be at least {min_length} characters long.")

        # Ensure the provided old_password is correct for the current key
        # This is an extra check before creating the temporary crypto handler
        try:
            self._crypto.unlock_with_master_password(old_password)
        except IncorrectPasswordError:
            # Re-raise to give clear feedback to the user
            raise IncorrectPasswordError("The provided 'old' master password was incorrect.")

        old_crypto_handler = CryptoHandler(str(self._data_dir))
        old_crypto_handler.unlock_with_master_password(old_password)
        
        self._crypto.change_master_password(old_password, new_password)
        self._db.re_encrypt_all_data(old_crypto_handler)

    # --- [修改] 更新文档字符串 ---
    def destroy_vault(self) -> None:
        """
        Permanently and securely deletes all vault files.

        This action first attempts to overwrite all files with random data to
        prevent simple data recovery, and then deletes the entire directory.
        This is irreversible. Use with extreme caution.

        .. warning:: Due to the nature of modern filesystems and storage
                     devices (especially SSDs), this method cannot guarantee
                     that the data is forensically unrecoverable. For maximum
                     security, rely on full-disk encryption.
        """
        if self.is_unlocked:
            self.lock()
        
        if self._data_dir.exists():
            logger.warning(f"Starting to securely destroy vault at: {self._data_dir}")
            for root, _, files in os.walk(self._data_dir):
                for name in files:
                    file_path = Path(root) / name
                    _secure_delete(file_path)
            
            shutil.rmtree(self._data_dir)
            logger.info(f"Vault at {self._data_dir} has been permanently destroyed.")

    # --- [修改] 导入/导出 API 封装 ---

    def export_to_skey(self, export_path: str) -> None:
        # (无变化)
        if not self.is_unlocked:
            raise VaultLockedError("Vault must be unlocked to export data.")
        
        from . import data_formats
        
        entries = self.get_all_entries()
        salt = self._crypto.get_salt()
        if not salt:
            raise OracipherError("Could not retrieve salt for export.")
            
        encrypted_content = data_formats.export_to_encrypted_json(
            entries=entries, salt=salt, encrypt_func=self._crypto.encrypt
        )
        Path(export_path).write_bytes(encrypted_content)
        logger.info(f"Vault securely exported to {export_path}")

    # --- [修改] 从静态方法重构为实例方法 ---
    def import_from_skey(self, skey_path: str, backup_password: str) -> None:
        """
        Decrypts an .skey file and imports its entries into this vault.

        This method encapsulates the complex decryption and import logic.
        """
        if not self.is_unlocked:
            raise VaultLockedError("Target vault must be unlocked to import entries.")

        from . import data_formats

        try:
            file_content_bytes = Path(skey_path).read_bytes()
            
            payload = json.loads(file_content_bytes)
            salt_from_file = base64.b64decode(payload['salt'])
            
            # Use the static _get_current_argon2_params for now. A more advanced
            # .skey format could also embed the params used for its encryption.
            temp_key = CryptoHandler._derive_key(
                backup_password, 
                salt_from_file, 
                CryptoHandler._get_current_argon2_params()
            )
            decryptor = Fernet(temp_key).decrypt

            imported_entries = data_formats.import_from_encrypted_json(
                file_content_bytes=file_content_bytes, decrypt_func=decryptor
            )
            
            if imported_entries:
                # 使用 self._db 而不是 target_vault._db
                self._db.save_multiple_entries(imported_entries)
            
            logger.info(f"Successfully imported {len(imported_entries)} entries into the vault from {skey_path}.")
        except (FileNotFoundError, IsADirectoryError) as e:
            raise OracipherError(f"Cannot read skey file at {skey_path}: {e}") from e
        except (json.JSONDecodeError, KeyError, base64.binascii.Error) as e:
            raise InvalidFileFormatError("Invalid .skey file format.") from e
        except Exception as e:
            logger.error(f"Failed to import from .skey file: {e}", exc_info=True)
            raise InvalidFileFormatError("Import failed: Incorrect password or corrupt file.") from e