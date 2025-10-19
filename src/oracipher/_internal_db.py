# src/oracipher/_internal_db.py

import os
import sqlite3
import json
import logging
from typing import List, Dict, Any, Optional, Iterator

from .crypto import CryptoHandler
from .exceptions import CorruptDataError, OracipherError

logger = logging.getLogger(__name__)


class DataManager:
    """
    [Internal Class] Manages all direct interactions with the SQLite database.

    This class handles CRUD operations for entries and categories, ensuring
    all data is passed through the CryptoHandler for encryption/decryption.
    It should not be used directly by the end-user of the library.
    """

    def __init__(self, db_path: str, crypto_handler: CryptoHandler):
        self.db_path = db_path
        # 确保目录存在
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
            
        self.crypto = crypto_handler
        self.conn: Optional[sqlite3.Connection] = None

    def connect(self):
        """Establishes the database connection."""
        if self.conn is None:
            # [高优先级修复] 移除了此处的 `check_and_migrate_schema` 调用。
            # 迁移逻辑现在完全由 Vault 类在初始化时统一处理。
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._create_tables()

    def _create_tables(self) -> None:
        if not self.conn:
            return
        cursor = self.conn.cursor()
        # 开启外键约束以保证数据完整性
        cursor.execute("PRAGMA foreign_keys = ON")
        # 创建条目表
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY, category TEXT NOT NULL, name TEXT NOT NULL)"
        )
        # 创建详情表，与条目表一对一关联，并设置级联删除
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS details (entry_id INTEGER PRIMARY KEY, data TEXT NOT NULL, FOREIGN KEY (entry_id) REFERENCES entries (id) ON DELETE CASCADE)"
        )
        # 创建分类表
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS categories (name TEXT PRIMARY KEY NOT NULL, icon_data TEXT)"
        )
        self.conn.commit()

    def get_all_entries(self) -> List[Dict[str, Any]]:
        """
        Retrieves and decrypts all entries from the database.

        Note: This loads all entries into memory. For large vaults,
        consider using `get_all_entries_iter()` for better memory efficiency.

        Raises:
            CorruptDataError: If any entry's data fails to decrypt.
        """
        # 利用新的生成器方法来构建列表，减少代码重复
        return list(self.get_all_entries_iter())

    def get_all_entries_iter(self) -> Iterator[Dict[str, Any]]:
        """
        [新增性能优化] Retrieves and decrypts all entries from the database as a generator.

        This method yields one entry at a time, making it highly memory-efficient
        for very large vaults.

        Raises:
            CorruptDataError: If any entry's data fails to decrypt.
        """
        if not self.conn:
            raise OracipherError("Database is not connected.")
        
        query = "SELECT e.id, e.category, e.name, d.data FROM entries e JOIN details d ON e.id = d.entry_id"
        cursor = self.conn.cursor()
        
        try:
            cursor.execute(query)
            for row in cursor: # 直接迭代 cursor 以获得更好的内存性能
                entry_id, category, name, encrypted_data_str = row
                try:
                    decrypted_data_json: str = self.crypto.decrypt(encrypted_data_str)
                    details: Dict[str, Any] = json.loads(decrypted_data_json)
                    yield {
                        "id": entry_id,
                        "category": category,
                        "name": name,
                        "details": details,
                    }
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON for entry ID {entry_id}: {e}")
                    raise CorruptDataError(f"Data for entry ID {entry_id} is corrupt (invalid JSON).") from e
                except CorruptDataError as e:
                    logger.error(f"Failed to decrypt data for entry ID {entry_id}: {e}")
                    raise CorruptDataError(f"Data for entry ID {entry_id} is corrupt.") from e
        finally:
            cursor.close()

    def save_entry(self, entry_data: Dict[str, Any]) -> int:
        """
        Saves a single entry (creates or updates).
        """
        if not self.conn:
            raise OracipherError("Database is not connected.")

        entry_id = entry_data.get("id")
        category = entry_data.get("category", "")
        name = entry_data.get("name")
        details = entry_data.get("details", {})

        if not name:
            raise ValueError("Entry 'name' cannot be empty.")

        encrypted_data = self.crypto.encrypt(json.dumps(details))
        
        with self.conn as conn: # 使用 'with' 语句自动处理事务
            cursor = conn.cursor()
            if entry_id is not None:
                cursor.execute(
                    "UPDATE entries SET category=?, name=? WHERE id=?", (category, name, entry_id)
                )
                cursor.execute(
                    "UPDATE details SET data=? WHERE entry_id=?", (encrypted_data, entry_id)
                )
            else:
                cursor.execute(
                    "INSERT INTO entries (category, name) VALUES (?, ?)", (category, name)
                )
                new_entry_id = cursor.lastrowid
                if new_entry_id is None:
                    # 在 'with' 块中，如果发生错误，事务会自动回滚
                    raise OracipherError("Failed to retrieve last inserted row ID.")
                entry_id = new_entry_id
                cursor.execute(
                    "INSERT INTO details (entry_id, data) VALUES (?, ?)", (entry_id, encrypted_data)
                )
            return entry_id

    def save_multiple_entries(self, entries: List[Dict[str, Any]]) -> None:
        """
        Saves a batch of entries in a single transaction. Assumes entries are new.
        """
        if not self.conn or not entries:
            return
            
        with self.conn as conn:
            cursor = conn.cursor()
            for entry in entries:
                name = entry.get("name")
                if not name:
                    continue 

                category = entry.get("category", "")
                details = entry.get("details", {})
                encrypted_data = self.crypto.encrypt(json.dumps(details))
                
                cursor.execute(
                    "INSERT INTO entries (category, name) VALUES (?, ?)", (category, name)
                )
                new_id = cursor.lastrowid
                if new_id is None:
                    raise OracipherError("Failed to get last row ID during bulk insert.")
                cursor.execute(
                    "INSERT INTO details (entry_id, data) VALUES (?, ?)", (new_id, encrypted_data)
                )
            logger.info(f"Bulk saved {len(entries)} entries.")

    def delete_entry(self, entry_id: int) -> None:
        """Deletes an entry by its ID."""
        if not self.conn:
            raise OracipherError("Database is not connected.")
        try:
            with self.conn as conn:
                conn.execute("DELETE FROM entries WHERE id=?", (entry_id,))
        except Exception as e:
            logger.error(f"Error deleting entry ID {entry_id}: {e}", exc_info=True)
            raise OracipherError(f"Failed to delete entry ID {entry_id}: {e}") from e

    def re_encrypt_all_data(self, old_crypto_handler: CryptoHandler) -> None:
        """
        [中优先级性能优化] Re-encrypts all data using batch processing to conserve memory.
        """
        if not self.conn:
            raise OracipherError("Database not connected.")
            
        read_cursor = self.conn.cursor()
        
        try:
            read_cursor.execute("SELECT entry_id, data FROM details")
            batch_size = 200  # 可配置的批处理大小
            total_re_encrypted = 0
            
            # 使用一个事务来包裹整个重加密过程，保证原子性
            with self.conn as conn:
                while True:
                    batch = read_cursor.fetchmany(batch_size)
                    if not batch:
                        break # 所有数据处理完毕
                    
                    re_encrypted_batch = []
                    for entry_id, encrypted_data in batch:
                        decrypted_json = old_crypto_handler.decrypt(encrypted_data)
                        new_encrypted_data = self.crypto.encrypt(decrypted_json)
                        re_encrypted_batch.append((new_encrypted_data, entry_id))
                    
                    conn.executemany(
                        "UPDATE details SET data = ? WHERE entry_id = ?",
                        re_encrypted_batch
                    )
                    total_re_encrypted += len(re_encrypted_batch)
                    logger.info(f"Re-encrypted batch of {len(re_encrypted_batch)} entries...")

            logger.info(f"Successfully re-encrypted a total of {total_re_encrypted} entries.")
            
        except Exception as e:
            # 'with' 语句会在异常时自动回滚
            logger.critical(f"A critical error occurred during data re-encryption: {e}", exc_info=True)
            raise OracipherError("Failed to re-encrypt vault data. The vault may be in an inconsistent state.") from e
        finally:
            read_cursor.close()

    def close(self) -> None:
        """Commits changes and closes the database connection."""
        if self.conn:
            try:
                self.conn.commit()
                self.conn.close()
            except Exception as e:
                logger.error(f"Error during database close: {e}", exc_info=True)
            finally:
                self.conn = None
    
    # --- Category Icon Methods ---

    def save_category_icon(self, category_name: str, icon_data_base64: str) -> None:
        if not self.conn:
            raise OracipherError("Database not connected.")
        try:
            with self.conn as conn:
                conn.execute(
                    "INSERT INTO categories (name, icon_data) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET icon_data=excluded.icon_data",
                    (category_name, icon_data_base64),
                )
        except Exception as e:
            raise OracipherError("Failed to save category icon.") from e

    def get_category_icons(self) -> Dict[str, str]:
        if not self.conn:
            raise OracipherError("Database not connected.")
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT name, icon_data FROM categories")
            return {
                name: icon_data
                for name, icon_data in cursor.fetchall()
                if icon_data
            }
        except Exception as e:
            raise OracipherError("Failed to retrieve category icons.") from e