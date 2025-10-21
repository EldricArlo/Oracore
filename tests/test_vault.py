# tests/test_vault.py

import pytest
from pathlib import Path

from oracore import Vault, OracipherError, VaultLockedError, VaultNotInitializedError, IncorrectPasswordError

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
    # Use min_length=0 to keep tests with existing passwords simple
    vault.setup(MASTER_PASSWORD, min_length=0) 
    vault.unlock(MASTER_PASSWORD)
    return vault

def test_vault_initialization(temp_vault_dir: Path):
    # (No change)
    assert not temp_vault_dir.exists()
    Vault(str(temp_vault_dir))
    assert temp_vault_dir.exists()

def test_setup_and_state(vault: Vault):
    # (No change)
    assert not vault.is_setup
    assert not vault.is_unlocked
    vault.setup(MASTER_PASSWORD)
    assert vault.is_setup
    assert vault.is_unlocked
    with pytest.raises(OracipherError, match="already initialized"):
        vault.setup("another-password")

# --- [新增] 测试密码强度验证 ---
def test_setup_with_short_password_fails(vault: Vault):
    """Test that setup fails with a password shorter than the minimum length."""
    with pytest.raises(ValueError, match="at least 12 characters long"):
        vault.setup("short", min_length=12)
    assert not vault.is_setup

    # Verify that disabling the check works
    vault.setup("short", min_length=0)
    assert vault.is_setup

def test_unlock_and_lock_cycle(vault: Vault):
    # (No change)
    vault.setup(MASTER_PASSWORD)
    assert vault.is_unlocked
    vault.lock()
    assert not vault.is_unlocked
    vault.unlock(MASTER_PASSWORD)
    assert vault.is_unlocked

def test_unlock_failures(vault: Vault):
    # (No change)
    with pytest.raises(VaultNotInitializedError):
        vault.unlock(MASTER_PASSWORD)
    vault.setup(MASTER_PASSWORD)
    vault.lock()
    with pytest.raises(IncorrectPasswordError):
        vault.unlock("wrong-password")

def test_operations_when_locked(unlocked_vault: Vault):
    # (No change)
    unlocked_vault.lock()
    assert not unlocked_vault.is_unlocked
    with pytest.raises(VaultLockedError):
        unlocked_vault.get_all_entries()
    with pytest.raises(VaultLockedError):
        unlocked_vault.save_entry({"name": "test"})
    with pytest.raises(VaultLockedError):
        unlocked_vault.delete_entry(1)
    with pytest.raises(VaultLockedError):
        unlocked_vault.change_master_password("a", "b", min_length=0)

def test_crud_operations(unlocked_vault: Vault):
    # (No change)
    entry_data = {"name": "Test Entry", "category": "Tests", "details": {"user": "test"}}
    entry_id = unlocked_vault.save_entry(entry_data)
    assert isinstance(entry_id, int)
    entries = unlocked_vault.get_all_entries()
    assert len(entries) == 1
    entries[0]["details"]["user"] = "updated_user"
    unlocked_vault.save_entry(entries[0])
    updated_entries = unlocked_vault.get_all_entries()
    assert updated_entries[0]["details"]["user"] == "updated_user"
    unlocked_vault.delete_entry(entry_id)
    final_entries = unlocked_vault.get_all_entries()
    assert len(final_entries) == 0

def test_change_master_password(unlocked_vault: Vault):
    # (No change)
    unlocked_vault.change_master_password(MASTER_PASSWORD, NEW_PASSWORD, min_length=0)
    assert unlocked_vault.is_unlocked
    unlocked_vault.lock()
    with pytest.raises(IncorrectPasswordError):
        unlocked_vault.unlock(MASTER_PASSWORD)
    unlocked_vault.unlock(NEW_PASSWORD)
    assert unlocked_vault.is_unlocked

# --- [新增] 测试新密码的强度验证 ---
def test_change_master_password_with_short_new_password_fails(unlocked_vault: Vault):
    """Test that changing to a short password fails."""
    with pytest.raises(ValueError, match="at least 12 characters"):
        unlocked_vault.change_master_password(MASTER_PASSWORD, "short-new", min_length=12)
    
    # Verify the vault is still unlocked with the old key
    assert unlocked_vault.is_unlocked
    unlocked_vault.lock()
    unlocked_vault.unlock(MASTER_PASSWORD)
    assert unlocked_vault.is_unlocked

def test_destroy_vault(unlocked_vault: Vault, temp_vault_dir: Path):
    # (No change)
    assert temp_vault_dir.exists()
    unlocked_vault.destroy_vault()
    assert not temp_vault_dir.exists()

# --- [核心修改] 更新导入 API 调用方式 ---
def test_skey_export_import(unlocked_vault: Vault, temp_vault_dir: Path):
    """Test the full export to .skey and import from .skey cycle."""
    export_path = temp_vault_dir / "backup.skey"
    unlocked_vault.save_entry({"name": "Data to Export"})
    
    unlocked_vault.export_to_skey(str(export_path))
    assert export_path.exists()
    
    unlocked_vault.lock()
    
    import_vault_dir = temp_vault_dir / "import_vault"
    import_vault = Vault(str(import_vault_dir))
    import_vault.setup("import-password", min_length=0)
    
    # [修改] 调用实例方法而不是静态方法
    import_vault.import_from_skey(
        skey_path=str(export_path),
        backup_password=MASTER_PASSWORD
    )
    
    imported_entries = import_vault.get_all_entries()
    assert len(imported_entries) == 1
    assert imported_entries[0]["name"] == "Data to Export"