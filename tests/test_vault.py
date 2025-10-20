# tests/test_vault.py

import pytest
from pathlib import Path

from oracipher import Vault, OracipherError, VaultLockedError, VaultNotInitializedError, IncorrectPasswordError

MASTER_PASSWORD = "test-password-123"
NEW_PASSWORD = "new-password-456"

@pytest.fixture
def temp_vault_dir(tmp_path: Path) -> Path:
    return tmp_path / "test_vault"

@pytest.fixture
def vault(temp_vault_dir: Path) -> Vault:
    return Vault(str(temp_vault_dir))

@pytest.fixture
def unlocked_vault(vault: Vault) -> Vault:
    vault.setup(MASTER_PASSWORD)
    vault.unlock(MASTER_PASSWORD)
    return vault

def test_vault_initialization(temp_vault_dir: Path):
    """Test that Vault initialization creates the data directory."""
    assert not temp_vault_dir.exists()
    Vault(str(temp_vault_dir))
    assert temp_vault_dir.exists()

def test_setup_and_state(vault: Vault):
    """Test the setup process and resulting state."""
    assert not vault.is_setup
    assert not vault.is_unlocked
    
    vault.setup(MASTER_PASSWORD)
    assert vault.is_setup
    assert vault.is_unlocked

    with pytest.raises(OracipherError, match="already initialized"):
        vault.setup("another-password")

def test_unlock_and_lock_cycle(vault: Vault):
    """Test the lock/unlock functionality."""
    vault.setup(MASTER_PASSWORD)
    assert vault.is_unlocked
    
    vault.lock()
    assert not vault.is_unlocked
    
    vault.unlock(MASTER_PASSWORD)
    assert vault.is_unlocked

def test_unlock_failures(vault: Vault):
    """Test various scenarios where unlock should fail."""
    with pytest.raises(VaultNotInitializedError):
        vault.unlock(MASTER_PASSWORD)
        
    vault.setup(MASTER_PASSWORD)
    vault.lock()
    
    with pytest.raises(IncorrectPasswordError):
        vault.unlock("wrong-password")

def test_operations_when_locked(unlocked_vault: Vault):
    """Ensure data operations raise VaultLockedError when the vault is locked."""
    unlocked_vault.lock()
    assert not unlocked_vault.is_unlocked
    
    with pytest.raises(VaultLockedError):
        unlocked_vault.get_all_entries()
    with pytest.raises(VaultLockedError):
        unlocked_vault.save_entry({"name": "test"})
    with pytest.raises(VaultLockedError):
        unlocked_vault.delete_entry(1)
    with pytest.raises(VaultLockedError):
        unlocked_vault.change_master_password("a", "b")

def test_crud_operations(unlocked_vault: Vault):
    """Test Create, Read, Update, Delete functionality."""
    # Create
    entry_data = {"name": "Test Entry", "category": "Tests", "details": {"user": "test"}}
    entry_id = unlocked_vault.save_entry(entry_data)
    assert isinstance(entry_id, int)
    
    # Read
    entries = unlocked_vault.get_all_entries()
    assert len(entries) == 1
    assert entries[0]["name"] == "Test Entry"
    assert entries[0]["details"]["user"] == "test"
    
    # Update
    entries[0]["details"]["user"] = "updated_user"
    unlocked_vault.save_entry(entries[0])
    updated_entries = unlocked_vault.get_all_entries()
    assert updated_entries[0]["details"]["user"] == "updated_user"
    
    # Delete
    unlocked_vault.delete_entry(entry_id)
    final_entries = unlocked_vault.get_all_entries()
    assert len(final_entries) == 0

def test_change_master_password(unlocked_vault: Vault):
    """Test the master password change workflow."""
    unlocked_vault.change_master_password(MASTER_PASSWORD, NEW_PASSWORD)
    
    # It should remain unlocked with the new key
    assert unlocked_vault.is_unlocked
    
    unlocked_vault.lock()
    
    # Old password should fail
    with pytest.raises(IncorrectPasswordError):
        unlocked_vault.unlock(MASTER_PASSWORD)
        
    # New password should succeed
    unlocked_vault.unlock(NEW_PASSWORD)
    assert unlocked_vault.is_unlocked

def test_destroy_vault(unlocked_vault: Vault, temp_vault_dir: Path):
    """Test that destroy_vault securely removes all files."""
    assert temp_vault_dir.exists()
    unlocked_vault.destroy_vault()
    assert not temp_vault_dir.exists()

def test_skey_export_import(unlocked_vault: Vault, temp_vault_dir: Path):
    """Test the full export to .skey and import from .skey cycle."""
    export_path = temp_vault_dir / "backup.skey"
    
    # Add an entry to export
    unlocked_vault.save_entry({"name": "Data to Export"})
    
    # Export
    unlocked_vault.export_to_skey(str(export_path))
    assert export_path.exists()
    
    # Lock the original vault
    unlocked_vault.lock()
    
    # Create a new, separate vault to import into
    import_vault_dir = temp_vault_dir / "import_vault"
    import_vault = Vault(str(import_vault_dir))
    import_vault.setup("import-password")
    
    # Import
    Vault.import_from_skey(
        skey_path=str(export_path),
        backup_password=MASTER_PASSWORD, # Use the password of the vault that created the backup
        target_vault=import_vault
    )
    
    # Verify
    imported_entries = import_vault.get_all_entries()
    assert len(imported_entries) == 1
    assert imported_entries[0]["name"] == "Data to Export"