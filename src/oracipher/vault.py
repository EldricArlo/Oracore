# src/oracipher/vault.py

import os
import shutil
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Iterator

from .crypto import CryptoHandler
from ._internal_db import DataManager
from .exceptions import VaultLockedError, OracipherError, VaultNotInitializedError
from ._internal_migration import check_and_migrate_schema

logger = logging.getLogger(__name__)

def _secure_delete(path: Path, passes: int = 1):
    """
    [新增安全功能] Securely deletes a file by first overwriting it with random data.
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

        Args:
            data_dir: The directory where the vault's database and key files
                      are stored. It will be created if it doesn't exist.
        """
        # [修改] 使用 pathlib 进行路径管理
        self._data_dir = Path(data_dir)
        self.db_path = self._data_dir / "safekey.db"

        # [架构职责] 迁移检查是 Vault 层的职责，在任何组件初始化之前执行。
        # 这样可以确保在 CryptoHandler 或 DataManager 接触任何文件之前，
        # 旧的数据库（如果存在）已经被安全地备份。
        check_and_migrate_schema(str(self.db_path))

        # 初始化底层处理器
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
        This will create the necessary key files and the database.
        """
        if self.is_setup:
            raise OracipherError("Vault is already initialized.")
        self._crypto.set_master_password(master_password)
        # 首次设置后立即连接，以创建数据库表
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

        Note: For very large vaults, consider using `get_all_entries_iter()`
        to avoid high memory consumption.
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault must be unlocked to retrieve entries.")
        return self._db.get_all_entries()

    def get_all_entries_iter(self) -> Iterator[Dict[str, Any]]:
        """
        [新增性能接口] Retrieves all entries as a memory-efficient iterator.
        
        This is recommended for applications handling large vaults.
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
        Changes the master password for the vault. This critical operation
        re-encrypts all data with a new key.
        """
        if not self.is_unlocked:
            raise VaultLockedError("Vault must be unlocked to change the master password.")

        # Create a temporary CryptoHandler instance to decrypt data with the old key.
        # This is safe as self._crypto is already unlocked with the same old key.
        old_crypto_handler = CryptoHandler(str(self._data_dir))
        old_crypto_handler.unlock_with_master_password(old_password)
        
        # 1. Change the key at the crypto layer (re-encrypts verification.key)
        self._crypto.change_master_password(old_password, new_password)
        
        # 2. Re-encrypt all database data using the new key
        self._db.re_encrypt_all_data(old_crypto_handler)

    def destroy_vault(self) -> None:
        """
        [高优先级安全修改] Permanently and securely deletes all vault files.

        This action first overwrites all files with random data to prevent
        data recovery and then deletes the entire directory.
        This is irreversible. Use with extreme caution.
        """
        if self.is_unlocked:
            self.lock()
        
        if self._data_dir.exists():
            logger.warning(f"Starting to securely destroy vault at: {self._data_dir}")
            # Securely delete all files within the directory first
            for root, _, files in os.walk(self._data_dir):
                for name in files:
                    file_path = Path(root) / name
                    _secure_delete(file_path)
            
            # Now, safely remove the (now empty) directory structure
            shutil.rmtree(self._data_dir)
            logger.info(f"Vault at {self._data_dir} has been permanently destroyed.")