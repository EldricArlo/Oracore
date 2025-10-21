# basic_usage.py

"""
A detailed and comprehensive example script demonstrating the core
features of the oracore library after the review committee's updates.
"""

import os
import shutil

# --- [核心修改] 将 'oracipher' 修改为 'oracore' ---
from oracore import (
    Vault,
    data_formats,
    IncorrectPasswordError,
    InvalidFileFormatError,
    OracipherError,  # OracipherError 这个异常基类的名字我们保持不变，因为它在库中已定义
)

# --- [修改] 更新示例目录和文件名以保持一致性 ---
DATA_DIRECTORY = "./my_oracore_vault"
MASTER_PASSWORD = "a-very-secure-password-!@#$%"
NEW_MASTER_PASSWORD = "a-much-better-password-&*(^)"
EXPORT_FILE_PATH = "./oracore_backup.skey"


def demonstrate_setup_and_unlock() -> Vault:
    """
    Shows the initial setup process and the standard unlock procedure.
    """
    print("--- 1. VAULT SETUP & UNLOCK DEMO ---")
    
    vault = Vault(DATA_DIRECTORY)
    print(f"Vault instance created for directory: '{DATA_DIRECTORY}'")

    if not vault.is_setup:
        print("Vault is not set up. Performing first-time setup...")
        # [注] setup() 现在会默认检查密码长度是否至少为12。
        # 可以通过 vault.setup(password, min_length=0) 禁用此检查。
        vault.setup(MASTER_PASSWORD)
        print("✅ Vault setup complete. Key files have been created.")
    else:
        print("Vault already exists. Skipping setup.")

    print("\nAttempting to unlock with an INCORRECT password...")
    try:
        vault.unlock("this-is-wrong")
    except IncorrectPasswordError:
        print("✅ Correctly caught 'IncorrectPasswordError' as expected.")
    
    print("\nAttempting to unlock with the CORRECT password...")
    try:
        vault.unlock(MASTER_PASSWORD)
        print("✅ Vault unlocked successfully! The encryption key is now in memory.")
        assert vault.is_unlocked
    except OracipherError as e:
        print(f"❌ An unexpected error occurred during unlock: {e}")

    return vault


def demonstrate_crud_operations(vault: Vault):
    """
    Demonstrates Create, Read, Update, and Delete operations.
    """
    print("\n--- 2. CRUD OPERATIONS DEMO ---")
    if not vault.is_unlocked:
        print("❌ CRUD demo skipped: Vault is locked.")
        return

    print("Saving new entries...")
    id1 = vault.save_entry({
        "name": "Google Account", "category": "Personal",
        "details": {"username": "my.email@gmail.com", "password": "generated_password_1"}
    })
    id2 = vault.save_entry({
        "name": "Work GitHub", "category": "Work",
        "details": {"username": "work_user", "password": "generated_password_2"}
    })
    print(f"✅ Saved 'Google' (ID: {id1}) and 'GitHub' (ID: {id2}).")

    all_entries = vault.get_all_entries()
    print(f"\nFound {len(all_entries)} entries in the vault.")

    print("\nUpdating Google Account password...")
    google_entry_to_update = next((e for e in all_entries if e['id'] == id1), None)
    if google_entry_to_update:
        google_entry_to_update['details']['password'] = "a_new_updated_password_3"
        vault.save_entry(google_entry_to_update)
        print("✅ Password updated.")

    print("\nDeleting Work GitHub entry...")
    vault.delete_entry(id2)
    print("✅ Entry deleted.")
    final_entries = vault.get_all_entries()
    print(f"Final entry count: {len(final_entries)}")
    assert len(final_entries) == 1


def demonstrate_password_change(vault: Vault):
    """
    Shows how to securely change the master password and verifies the change.
    """
    print("\n--- 3. MASTER PASSWORD CHANGE DEMO ---")
    if not vault.is_unlocked:
        print("❌ Password change demo skipped: Vault is locked.")
        return

    print("Attempting to change password with INCORRECT old password...")
    try:
        vault.change_master_password("wrong-old-password", NEW_MASTER_PASSWORD)
    except IncorrectPasswordError:
        print("✅ Correctly caught 'IncorrectPasswordError'.")

    print("\nChanging master password correctly...")
    # [注] change_master_password() 同样会检查新密码的最小长度。
    vault.change_master_password(MASTER_PASSWORD, NEW_MASTER_PASSWORD)
    print("✅ Master password changed successfully. All data has been re-encrypted.")

    print("Verifying the change...")
    vault.lock()
    print("  - Vault locked.")
    
    print("  - Attempting to unlock with OLD password...")
    try:
        vault.unlock(MASTER_PASSWORD)
    except IncorrectPasswordError:
        print("  - ✅ Correctly failed as expected.")

    print("  - Attempting to unlock with NEW password...")
    vault.unlock(NEW_MASTER_PASSWORD)
    print("  - ✅ Unlocked successfully with the new password!")
    assert vault.is_unlocked


def demonstrate_export_import(vault: Vault):
    """
    Demonstrates exporting to CSV and the secure .skey format, then importing back.
    """
    print("\n--- 4. EXPORT / IMPORT DEMO ---")
    if not vault.is_unlocked:
        print("❌ Export/Import demo skipped: Vault is locked.")
        return

    # 1. Export to unencrypted CSV (for compatibility)
    print("Exporting to CSV format...")
    entries = vault.get_all_entries()
    csv_data = data_formats.export_to_csv(entries)
    print("--- CSV START ---")
    print(csv_data.strip())
    print("--- CSV END ---\n")

    # 2. Export to encrypted .skey format
    print(f"Exporting to secure .skey format at '{EXPORT_FILE_PATH}'...")
    try:
        vault.export_to_skey(EXPORT_FILE_PATH)
        print("✅ Secure backup file created.")
    except Exception as e:
        print(f"❌ Export failed: {e}")
        return

    # 3. Import from the encrypted .skey file
    print(f"\nImporting from '{EXPORT_FILE_PATH}'...")
    try:
        # [核心修改] 调用实例方法 `vault.import_from_skey` 而不是静态方法。
        # The backup_password is the password of the vault that CREATED the backup.
        # Since we changed the password before exporting, we must use the NEW password here.
        vault.import_from_skey(
            skey_path=EXPORT_FILE_PATH,
            backup_password=NEW_MASTER_PASSWORD
        )
        print(f"✅ Successfully decrypted and imported entries.")
        
        all_entries = vault.get_all_entries()
        print(f"Total entries after import: {len(all_entries)}")
        assert len(all_entries) == 2 # 1 original + 1 imported
        
    except InvalidFileFormatError as e:
        print(f"❌ Import failed: Incorrect password or corrupt file. {e}")
    except Exception as e:
        print(f"❌ An unexpected error occurred during import: {e}")


def demonstrate_destruction(vault: Vault):
    """
    Shows the IRREVERSIBLE process of destroying a vault.
    """
    print("\n--- 5. VAULT DESTRUCTION DEMO ---")
    print("⚠️ WARNING: This action is IRREVERSIBLE and will securely delete all vault data.")
    print("Destruction demo is commented out for safety. To run, edit the script.")
    # confirm = input("Type 'DELETE' to confirm vault destruction: ")
    # if confirm == "DELETE":
    #     print("Destroying vault...")
    #     vault.destroy_vault()
    #     print("✅ Vault has been securely destroyed.")
    #     assert not os.path.exists(DATA_DIRECTORY)
    # else:
    #     print("Destruction cancelled.")


def main():
    """
    Main function to run all demonstrations.
    """
    if os.path.exists(DATA_DIRECTORY):
        shutil.rmtree(DATA_DIRECTORY)
    if os.path.exists(EXPORT_FILE_PATH):
        os.remove(EXPORT_FILE_PATH)
        
    vault = None
    try:
        vault = demonstrate_setup_and_unlock()
        demonstrate_crud_operations(vault)
        demonstrate_password_change(vault)
        demonstrate_export_import(vault)
        demonstrate_destruction(vault)
    except Exception as e:
        print(f"\n💥 An unexpected critical error occurred: {e}")
    finally:
        if vault and vault.is_unlocked:
            vault.lock()
            print("\n--- FINALIZATION ---")
            print("✅ Vault has been locked to ensure data safety.")


if __name__ == "__main__":
    main()