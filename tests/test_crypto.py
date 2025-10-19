# tests/test_crypto.py

"""
Unit tests for the CryptoHandler class in the oracipher library.
"""

import os
import pytest
from pathlib import Path  # [新增] 导入 Path 以便在测试中进行路径操作

from oracipher.crypto import CryptoHandler
from oracipher.exceptions import (
    IncorrectPasswordError,
    VaultNotInitializedError,
    VaultLockedError,
    CorruptDataError,
)

# --- Test Constants ---
MASTER_PASSWORD = "my-strong-password-123"
INCORRECT_PASSWORD = "wrong-password"
NEW_PASSWORD = "a-new-secure-password-456"
TEST_DATA = "This is some secret data for testing."


# --- Pytest Fixtures ---

@pytest.fixture
def temp_data_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for test artifacts."""
    return tmp_path

@pytest.fixture
def crypto_handler(temp_data_dir: Path) -> CryptoHandler:
    """Return a fresh, uninitialized CryptoHandler instance for each test."""
    # 显式转换为字符串以匹配 __init__ 的类型提示
    return CryptoHandler(data_dir=str(temp_data_dir))

@pytest.fixture
def initialized_crypto_handler(crypto_handler: CryptoHandler) -> CryptoHandler:
    """Return a CryptoHandler that has already been set up and is unlocked."""
    crypto_handler.set_master_password(MASTER_PASSWORD)
    return crypto_handler


# --- Test Cases ---

def test_initialization_creates_data_dir(tmp_path: Path):
    """Test that the data directory is created if it doesn't exist."""
    # [修改] 使用 pathlib 进行路径操作
    data_dir = tmp_path / "new_dir"
    assert not data_dir.exists()
    CryptoHandler(data_dir=str(data_dir))
    assert data_dir.exists()

def test_set_master_password_creates_files_and_unlocks(initialized_crypto_handler: CryptoHandler):
    """Test that setting the master password creates salt/verification files and unlocks the vault."""
    handler = initialized_crypto_handler
    # [修改] 使用 pathlib 对象的 .exists() 方法
    assert handler.salt_path.exists()
    assert handler.verification_path.exists()
    assert handler.is_unlocked is True

def test_unlock_with_correct_password_succeeds(initialized_crypto_handler: CryptoHandler):
    """Test that unlocking with the correct password works as expected."""
    handler = initialized_crypto_handler
    handler.lock()
    assert handler.is_unlocked is False

    handler.unlock_with_master_password(MASTER_PASSWORD)
    assert handler.is_unlocked is True

def test_unlock_with_incorrect_password_raises_error(initialized_crypto_handler: CryptoHandler):
    """Test that using an incorrect password raises IncorrectPasswordError."""
    handler = initialized_crypto_handler
    handler.lock()
    
    with pytest.raises(IncorrectPasswordError):
        handler.unlock_with_master_password(INCORRECT_PASSWORD)
    
    assert handler.is_unlocked is False

def test_unlock_uninitialized_vault_raises_error(crypto_handler: CryptoHandler):
    """Test that trying to unlock an uninitialized vault raises VaultNotInitializedError."""
    with pytest.raises(VaultNotInitializedError):
        crypto_handler.unlock_with_master_password(MASTER_PASSWORD)

def test_lock_clears_key(initialized_crypto_handler: CryptoHandler):
    """Test that the lock() method clears the key and sets is_unlocked to False."""
    handler = initialized_crypto_handler
    assert handler.is_unlocked is True
    
    handler.lock()
    assert handler.is_unlocked is False

def test_encrypt_decrypt_cycle_succeeds(initialized_crypto_handler: CryptoHandler):
    """Test a full encrypt -> decrypt cycle with valid data."""
    handler = initialized_crypto_handler
    encrypted = handler.encrypt(TEST_DATA)
    
    assert isinstance(encrypted, str)
    assert encrypted != TEST_DATA
    
    decrypted = handler.decrypt(encrypted)
    assert decrypted == TEST_DATA

def test_encrypt_when_locked_raises_error(initialized_crypto_handler: CryptoHandler):
    """Test that encrypting data while the vault is locked raises VaultLockedError."""
    handler = initialized_crypto_handler
    handler.lock()
    
    with pytest.raises(VaultLockedError):
        handler.encrypt(TEST_DATA)

def test_decrypt_when_locked_raises_error(initialized_crypto_handler: CryptoHandler):
    """Test that decrypting data while the vault is locked raises VaultLockedError."""
    handler = initialized_crypto_handler
    encrypted_data = handler.encrypt(TEST_DATA)
    handler.lock()
    
    with pytest.raises(VaultLockedError):
        handler.decrypt(encrypted_data)

def test_decrypt_with_corrupt_data_raises_error(initialized_crypto_handler: CryptoHandler):
    """Test that decrypting tampered/corrupt data raises CorruptDataError."""
    handler = initialized_crypto_handler
    corrupt_data = "this-is-not-valid-fernet-data"
    
    with pytest.raises(CorruptDataError):
        handler.decrypt(corrupt_data)
        
    encrypted_data = handler.encrypt(TEST_DATA)
    tampered_data = encrypted_data[:-1] + 'a' # Modify the last character
    
    with pytest.raises(CorruptDataError):
        handler.decrypt(tampered_data)
        
def test_change_master_password_succeeds(initialized_crypto_handler: CryptoHandler):
    """Test that the master password can be changed successfully."""
    handler = initialized_crypto_handler
    handler.change_master_password(old_password=MASTER_PASSWORD, new_password=NEW_PASSWORD)
    
    assert handler.is_unlocked is True
    
    handler.lock()
    handler.unlock_with_master_password(NEW_PASSWORD)
    assert handler.is_unlocked is True

def test_unlocking_with_old_password_fails_after_change(initialized_crypto_handler: CryptoHandler):
    """Test that the old password no longer works after a change."""
    handler = initialized_crypto_handler
    handler.change_master_password(old_password=MASTER_PASSWORD, new_password=NEW_PASSWORD)
    handler.lock()

    with pytest.raises(IncorrectPasswordError):
        handler.unlock_with_master_password(MASTER_PASSWORD)

def test_change_master_password_with_incorrect_old_password_raises_error(initialized_crypto_handler: CryptoHandler):
    """Test that changing password with a wrong 'old' password fails."""
    handler = initialized_crypto_handler
    
    with pytest.raises(IncorrectPasswordError):
        handler.change_master_password(old_password=INCORRECT_PASSWORD, new_password=NEW_PASSWORD)
    
    handler.lock()
    handler.unlock_with_master_password(MASTER_PASSWORD)
    assert handler.is_unlocked is True

def test_is_key_setup_before_initialization(crypto_handler: CryptoHandler):
    """Test is_key_setup() returns False for a new instance."""
    assert crypto_handler.is_key_setup() is False

def test_is_key_setup_after_initialization(initialized_crypto_handler: CryptoHandler):
    """Test is_key_setup() returns True after setting master password."""
    assert initialized_crypto_handler.is_key_setup() is True