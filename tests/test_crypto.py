# tests/test_crypto.py

"""
Unit tests for the CryptoHandler class in the oracipher library.
"""

import os
import pytest
from pathlib import Path
import json

from oracore.crypto import CryptoHandler
from oracore.exceptions import (
    IncorrectPasswordError,
    VaultNotInitializedError,
    VaultLockedError,
    CorruptDataError,
)

# --- Test Constants (no change) ---
MASTER_PASSWORD = "my-strong-password-123"
INCORRECT_PASSWORD = "wrong-password"
NEW_PASSWORD = "a-new-secure-password-456"
TEST_DATA = "This is some secret data for testing."


# --- Pytest Fixtures (no change) ---

@pytest.fixture
def temp_data_dir(tmp_path: Path) -> Path:
    return tmp_path

@pytest.fixture
def crypto_handler(temp_data_dir: Path) -> CryptoHandler:
    return CryptoHandler(data_dir=str(temp_data_dir))

@pytest.fixture
def initialized_crypto_handler(crypto_handler: CryptoHandler) -> CryptoHandler:
    crypto_handler.set_master_password(MASTER_PASSWORD)
    return crypto_handler


# --- Test Cases (one new test added) ---

def test_initialization_creates_data_dir(tmp_path: Path):
    # (No change)
    data_dir = tmp_path / "new_dir"
    assert not data_dir.exists()
    CryptoHandler(data_dir=str(data_dir))
    assert data_dir.exists()

def test_set_master_password_creates_files_and_unlocks(initialized_crypto_handler: CryptoHandler):
    # (No change, but now implicitly tests JSON file creation)
    handler = initialized_crypto_handler
    assert handler.salt_path.exists()
    assert handler.verification_path.exists()
    assert handler.is_unlocked is True
    # Optional: Add a check for valid JSON
    try:
        json.loads(handler.verification_path.read_text())
    except json.JSONDecodeError:
        pytest.fail("verification.key should contain valid JSON")

def test_unlock_with_correct_password_succeeds(initialized_crypto_handler: CryptoHandler):
    # (No change)
    handler = initialized_crypto_handler
    handler.lock()
    assert handler.is_unlocked is False
    handler.unlock_with_master_password(MASTER_PASSWORD)
    assert handler.is_unlocked is True

def test_unlock_with_incorrect_password_raises_error(initialized_crypto_handler: CryptoHandler):
    # (No change)
    handler = initialized_crypto_handler
    handler.lock()
    with pytest.raises(IncorrectPasswordError):
        handler.unlock_with_master_password(INCORRECT_PASSWORD)
    assert handler.is_unlocked is False

# --- [新增] 测试 KDF 版本控制的健壮性 ---
def test_unlock_with_corrupt_verification_file_raises_error(initialized_crypto_handler: CryptoHandler):
    """Test that unlocking fails gracefully if verification.key is corrupt."""
    handler = initialized_crypto_handler
    handler.lock()
    
    # Case 1: File is not valid JSON
    handler.verification_path.write_text("this-is-not-json")
    with pytest.raises(CorruptDataError):
        handler.unlock_with_master_password(MASTER_PASSWORD)
    
    # Case 2: File is valid JSON but missing the 'token' key
    handler.verification_path.write_text('{"params": {}}')
    with pytest.raises(CorruptDataError):
        handler.unlock_with_master_password(MASTER_PASSWORD)
        
    # Case 3: File is valid JSON but missing the 'params' key
    handler.verification_path.write_text('{"token": "abc"}')
    with pytest.raises(CorruptDataError):
        handler.unlock_with_master_password(MASTER_PASSWORD)

def test_unlock_uninitialized_vault_raises_error(crypto_handler: CryptoHandler):
    # (No change)
    with pytest.raises(VaultNotInitializedError):
        crypto_handler.unlock_with_master_password(MASTER_PASSWORD)

def test_lock_clears_key(initialized_crypto_handler: CryptoHandler):
    # (No change)
    handler = initialized_crypto_handler
    assert handler.is_unlocked is True
    handler.lock()
    assert handler.is_unlocked is False

def test_encrypt_decrypt_cycle_succeeds(initialized_crypto_handler: CryptoHandler):
    # (No change)
    handler = initialized_crypto_handler
    encrypted = handler.encrypt(TEST_DATA)
    assert isinstance(encrypted, str)
    assert encrypted != TEST_DATA
    decrypted = handler.decrypt(encrypted)
    assert decrypted == TEST_DATA

def test_encrypt_when_locked_raises_error(initialized_crypto_handler: CryptoHandler):
    # (No change)
    handler = initialized_crypto_handler
    handler.lock()
    with pytest.raises(VaultLockedError):
        handler.encrypt(TEST_DATA)

def test_decrypt_when_locked_raises_error(initialized_crypto_handler: CryptoHandler):
    # (No change)
    handler = initialized_crypto_handler
    encrypted_data = handler.encrypt(TEST_DATA)
    handler.lock()
    with pytest.raises(VaultLockedError):
        handler.decrypt(encrypted_data)

def test_decrypt_with_corrupt_data_raises_error(initialized_crypto_handler: CryptoHandler):
    # (No change)
    handler = initialized_crypto_handler
    corrupt_data = "this-is-not-valid-fernet-data"
    with pytest.raises(CorruptDataError):
        handler.decrypt(corrupt_data)
    encrypted_data = handler.encrypt(TEST_DATA)
    tampered_data = encrypted_data[:-1] + 'a'
    with pytest.raises(CorruptDataError):
        handler.decrypt(tampered_data)
        
def test_change_master_password_succeeds(initialized_crypto_handler: CryptoHandler):
    # (No change, but now implicitly tests KDF param upgrade path)
    handler = initialized_crypto_handler
    handler.change_master_password(old_password=MASTER_PASSWORD, new_password=NEW_PASSWORD)
    assert handler.is_unlocked is True
    handler.lock()
    handler.unlock_with_master_password(NEW_PASSWORD)
    assert handler.is_unlocked is True

def test_unlocking_with_old_password_fails_after_change(initialized_crypto_handler: CryptoHandler):
    # (No change)
    handler = initialized_crypto_handler
    handler.change_master_password(old_password=MASTER_PASSWORD, new_password=NEW_PASSWORD)
    handler.lock()
    with pytest.raises(IncorrectPasswordError):
        handler.unlock_with_master_password(MASTER_PASSWORD)

def test_change_master_password_with_incorrect_old_password_raises_error(initialized_crypto_handler: CryptoHandler):
    # (No change)
    handler = initialized_crypto_handler
    with pytest.raises(IncorrectPasswordError):
        handler.change_master_password(old_password=INCORRECT_PASSWORD, new_password=NEW_PASSWORD)
    handler.lock()
    handler.unlock_with_master_password(MASTER_PASSWORD)
    assert handler.is_unlocked is True

def test_is_key_setup_before_initialization(crypto_handler: CryptoHandler):
    # (No change)
    assert crypto_handler.is_key_setup() is False

def test_is_key_setup_after_initialization(initialized_crypto_handler: CryptoHandler):
    # (No change)
    assert initialized_crypto_handler.is_key_setup() is True