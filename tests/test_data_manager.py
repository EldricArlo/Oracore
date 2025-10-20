# tests/test_data_manager.py

import pytest
import sqlite3
import json
from typing import Dict, Any

from oracore._internal_db import DataManager, OracipherError

# A simple mock that mimics the encrypt/decrypt behavior for testing
class MockCryptoHandler:
    def encrypt(self, data: str) -> str:
        return "enc:" + data

    def decrypt(self, encrypted_data: str) -> str:
        if encrypted_data.startswith("enc:"):
            return encrypted_data[4:]
        raise ValueError("Invalid mock encrypted data")

@pytest.fixture
def crypto_handler() -> MockCryptoHandler:
    return MockCryptoHandler()

@pytest.fixture
def db_manager(crypto_handler: MockCryptoHandler) -> DataManager:
    """Creates a DataManager with an in-memory SQLite database for fast testing."""
    manager = DataManager(":memory:", crypto_handler)
    manager.connect()
    return manager

@pytest.fixture
def sample_entry() -> Dict[str, Any]:
    return {
        "name": "Sample",
        "category": "General",
        "details": {"username": "user", "password": "pass"}
    }

def test_create_tables(db_manager: DataManager):
    """Test if tables are created correctly."""
    conn = db_manager.conn
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {row[0] for row in cursor.fetchall()}
    assert "entries" in tables
    assert "details" in tables
    assert "categories" in tables

def test_save_and_get_entry(db_manager: DataManager, sample_entry: Dict[str, Any]):
    """Test saving a new entry and retrieving it."""
    entry_id = db_manager.save_entry(sample_entry)
    
    entries = db_manager.get_all_entries()
    assert len(entries) == 1
    retrieved = entries[0]
    
    assert retrieved["id"] == entry_id
    assert retrieved["name"] == sample_entry["name"]
    assert retrieved["details"] == sample_entry["details"]

def test_update_entry(db_manager: DataManager, sample_entry: Dict[str, Any]):
    """Test updating an existing entry."""
    entry_id = db_manager.save_entry(sample_entry)
    
    entry_to_update = db_manager.get_all_entries()[0]
    entry_to_update["name"] = "Updated Name"
    entry_to_update["details"]["password"] = "new_pass"
    
    updated_id = db_manager.save_entry(entry_to_update)
    assert updated_id == entry_id
    
    entries = db_manager.get_all_entries()
    assert len(entries) == 1
    assert entries[0]["name"] == "Updated Name"
    assert entries[0]["details"]["password"] == "new_pass"

def test_delete_entry(db_manager: DataManager, sample_entry: Dict[str, Any]):
    """Test deleting an entry."""
    entry_id = db_manager.save_entry(sample_entry)
    assert len(db_manager.get_all_entries()) == 1
    
    db_manager.delete_entry(entry_id)
    assert len(db_manager.get_all_entries()) == 0

def test_save_multiple_entries(db_manager: DataManager):
    """Test the batch save functionality."""
    entries_to_save = [
        {"name": "Entry 1", "details": {"a": "1"}},
        {"name": "Entry 2", "details": {"b": "2"}},
    ]
    db_manager.save_multiple_entries(entries_to_save)
    
    retrieved_entries = db_manager.get_all_entries()
    assert len(retrieved_entries) == 2
    names = {e["name"] for e in retrieved_entries}
    assert "Entry 1" in names
    assert "Entry 2" in names