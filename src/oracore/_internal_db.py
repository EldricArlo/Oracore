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
    """

    def __init__(self, db_path: str, crypto_handler: CryptoHandler):
        self.db_path = db_path
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
            
        self.crypto = crypto_handler
        self.conn: Optional[sqlite3.Connection] = None

    def connect(self):
        """Establishes the database connection."""
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._create_tables()

    def _create_tables(self) -> None:
        if not self.conn:
            return
        cursor = self.conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY, category TEXT NOT NULL, name TEXT NOT NULL)"
        )
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS details (entry_id INTEGER PRIMARY KEY, data TEXT NOT NULL, FOREIGN KEY (entry_id) REFERENCES entries (id) ON DELETE CASCADE)"
        )
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS categories (name TEXT PRIMARY KEY NOT NULL, icon_data TEXT)"
        )
        self.conn.commit()

    def get_all_entries(self) -> List[Dict[str, Any]]:
        """Retrieves and decrypts all entries from the database."""
        return list(self.get_all_entries_iter())

    def get_all_entries_iter(self) -> Iterator[Dict[str, Any]]:
        """Retrieves and decrypts all entries from the database as a generator."""
        if not self.conn:
            raise OracipherError("Database is not connected.")
        
        query = "SELECT e.id, e.category, e.name, d.data FROM entries e JOIN details d ON e.id = d.entry_id"
        cursor = self.conn.cursor()
        
        try:
            cursor.execute(query)
            for row in cursor:
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
        """Saves a single entry (creates or updates)."""
        if not self.conn:
            raise OracipherError("Database is not connected.")

        if not isinstance(entry_data, dict):
            raise TypeError("entry_data must be a dictionary.")
        if not entry_data.get("name") or not isinstance(entry_data.get("name"), str):
            raise ValueError("Entry 'name' must be a non-empty string.")
        if "details" in entry_data and not isinstance(entry_data.get("details"), dict):
            raise TypeError("Entry 'details' must be a dictionary.")

        entry_id = entry_data.get("id")
        category = entry_data.get("category", "")
        name = entry_data.get("name")
        details = entry_data.get("details", {})

        encrypted_data = self.crypto.encrypt(json.dumps(details))
        
        with self.conn as conn:
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
                    raise OracipherError("Failed to retrieve last inserted row ID.")
                entry_id = new_entry_id
                cursor.execute(
                    "INSERT INTO details (entry_id, data) VALUES (?, ?)", (entry_id, encrypted_data)
                )
            return entry_id

    def save_multiple_entries(self, entries: List[Dict[str, Any]]) -> None:
        """
        [修正] 恢复为循环插入的实现，以保证获取 lastrowid 的健壮性。
        整个操作依然在单个事务中完成，保证原子性。
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
                    # 'with' 块会确保在异常发生时回滚事务
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
        """Re-encrypts all data using batch processing to conserve memory."""
        if not self.conn:
            raise OracipherError("Database not connected.")
            
        read_cursor = self.conn.cursor()
        
        try:
            read_cursor.execute("SELECT entry_id, data FROM details")
            batch_size = 200
            total_re_encrypted = 0
            
            with self.conn as conn:
                while True:
                    batch = read_cursor.fetchmany(batch_size)
                    if not batch:
                        break
                    
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