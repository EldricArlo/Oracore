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
    InvalidFileFormatError
)
from ._internal_migration import check_and_migrate_schema
# cryptography.fernet 需要在导入方法中按需导入
# from cryptography.fernet import Fernet


logger = logging.getLogger(__name__)

def _secure_delete(path: Path, passes: int = 1):
    """
    Securely deletes a file by first overwriting it with random data.
    """
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
    """

    def __init__(self, data_dir: str):
        """
        Initializes a Vault instance.
        """
        self._data_dir = Path(data_dir)
        self.db_path = self._data_dir / "safekey.db"

        check_and_migrate_schema(str(self.db_path))

        self._crypto = CryptoHandler(str(self._data_dir))
        self._db = DataManager(str(self.db_path), self._crypto)

    @property
    def is_setup(self) -> bool:
        """Checks if the vault has been initialized with a master password."""
        return self._crypto.is_key_setup()

    @property
    def is_unlocked(self) -> bool:
        """Checks if the vault is currently unlocked."""
        return self._crypto.is_unlocked

    def setup(self, master_password: str) -> None:
        """
        Sets up the vault for the first time with a master password.
        """
        if self.is_setup:
            raise OracipherError("Vault is already initialized.")
        self._crypto.set_master_password(master_password)
        self._db.connect()

    def unlock(self, master_password: str) -> None:
        """
        Unlocks the vault with the master password.
        """
        if not self.is_setup:
            raise VaultNotInitializedError(
                "Vault has not been set up. Please call setup() first."
            )
        self._crypto.unlock_with_master_password(master_password)
        if self.is_unlocked:
            self._db.connect()

    def lock(self) -> None:
        """
        Locks the vault, clearing the key from memory and closing the DB connection.
        """
        self._crypto.lock()
        self._db.close()

    def get_all_entries(self) -> List[Dict[str, Any]]:
        """
        Retrieves all entries from the vault, loading them into a list.
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault must be unlocked to retrieve entries.")
        return self._db.get_all_entries()

    def get_all_entries_iter(self) -> Iterator[Dict[str, Any]]:
        """
        Retrieves all entries as a memory-efficient iterator.
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault must be unlocked to retrieve entries.")
        yield from self._db.get_all_entries_iter()

    def save_entry(self, entry_data: Dict[str, Any]) -> int:
        """
        Saves a single entry (creates a new one or updates an existing one).
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault must be unlocked to save an entry.")
        return self._db.save_entry(entry_data)
    
    def delete_entry(self, entry_id: int) -> None:
        """
        Deletes an entry by its ID.
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault must be unlocked to delete an entry.")
        self._db.delete_entry(entry_id)

    def change_master_password(self, old_password: str, new_password: str) -> None:
        """
        Changes the master password for the vault.
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault must be unlocked to change the master password.")

        old_crypto_handler = CryptoHandler(str(self._data_dir))
        old_crypto_handler.unlock_with_master_password(old_password)
        
        self._crypto.change_master_password(old_password, new_password)
        self._db.re_encrypt_all_data(old_crypto_handler)

    def destroy_vault(self) -> None:
        """
        Permanently and securely deletes all vault files.
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

    # --- [新增] 导入/导出 API 封装 ---

    def export_to_skey(self, export_path: str) -> None:
        """
        [新增] Securely exports all vault entries to an encrypted .skey file.

        This method encapsulates the entire secure export process.
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault must be unlocked to export data.")
        
        # 使用局部导入避免循环依赖
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

    @staticmethod
    def import_from_skey(
        skey_path: str, 
        backup_password: str, 
        target_vault: 'Vault'
    ) -> None:
        """
        [新增] Decrypts an .skey file and imports its entries into the target vault.

        This static method encapsulates the complex decryption and import logic,
        providing a simple and secure API for users.
        """
        if not target_vault.is_unlocked:
            raise VaultLockedError("Target vault must be unlocked to import entries.")

        from . import data_formats
        from cryptography.fernet import Fernet

        try:
            file_content_bytes = Path(skey_path).read_bytes()
            
            payload = json.loads(file_content_bytes)
            salt_from_file = base64.b64decode(payload['salt'])
            
            temp_key = CryptoHandler._derive_key(backup_password, salt_from_file)
            decryptor = Fernet(temp_key).decrypt

            imported_entries = data_formats.import_from_encrypted_json(
                file_content_bytes=file_content_bytes, decrypt_func=decryptor
            )
            
            if imported_entries:
                target_vault._db.save_multiple_entries(imported_entries)
            
            logger.info(f"Successfully imported {len(imported_entries)} entries into the vault from {skey_path}.")
        except (FileNotFoundError, IsADirectoryError) as e:
            raise OracipherError(f"Cannot read skey file at {skey_path}: {e}") from e
        except (json.JSONDecodeError, KeyError, base64.binascii.Error) as e:
            raise InvalidFileFormatError("Invalid .skey file format.") from e
        except Exception as e:
            # 捕获解密失败（密码错误）或其他意外错误
            logger.error(f"Failed to import from .skey file: {e}", exc_info=True)
            raise InvalidFileFormatError("Import failed: Incorrect password or corrupt file.") from e