# basic_usage.py

"""
A detailed and comprehensive example script demonstrating the core
features of the oracipher library.

This script covers:
1.  Initializing a new vault.
2.  First-time setup with a master password.
3.  The essential unlock -> operate -> lock security cycle.
4.  Handling incorrect password errors.
5.  CRUD operations: Creating, Reading, Updating, and Deleting entries.
6.  Changing the master password securely.
7.  Exporting data to different formats (unencrypted CSV and encrypted .skey).
8.  Importing data from an encrypted .skey backup file.
9.  Permanently and securely destroying the vault.
"""

import os
import shutil
import json
import base64
from getpass import getpass # Use getpass for safely typing passwords

# --- Oracipher Core Imports ---
from oracipher import (
    Vault,
    data_formats,
    IncorrectPasswordError,
    VaultNotInitializedError,
    OracipherError,
)

# --- Imports for Advanced Import/Export Demo ---
# These are needed to demonstrate the manual decryption process for imports
from oracipher.crypto import CryptoHandler 
from cryptography.fernet import Fernet

# --- Configuration ---
DATA_DIRECTORY = "./my_oracipher_vault"
MASTER_PASSWORD = "a-very-secure-password-!@#$%"
NEW_MASTER_PASSWORD = "a-much-better-password-&*(^)"
EXPORT_FILE_PATH = "./oracipher_backup.skey"


def demonstrate_setup_and_unlock() -> Vault:
    """
    Shows the initial setup process and the standard unlock procedure.
    """
    print("--- 1. VAULT SETUP & UNLOCK DEMO ---")
    
    # 1. Initialize the Vault object
    vault = Vault(DATA_DIRECTORY)
    print(f"Vault instance created for directory: '{DATA_DIRECTORY}'")

    # 2. First-time setup
    if not vault.is_setup:
        print("Vault is not set up. Performing first-time setup...")
        vault.setup(MASTER_PASSWORD)
        print("✅ Vault setup complete. Key files have been created.")
    else:
        print("Vault already exists. Skipping setup.")

    # 3. Demonstrate incorrect password handling
    print("\nAttempting to unlock with an INCORRECT password...")
    try:
        wrong_password = "this-is-wrong"
        vault.unlock(wrong_password)
    except IncorrectPasswordError:
        print("✅ Correctly caught 'IncorrectPasswordError' as expected.")
    
    # 4. Correctly unlock the vault
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
    Assumes the vault is already unlocked.
    """
    print("\n--- 2. CRUD OPERATIONS DEMO ---")
    if not vault.is_unlocked:
        print("❌ CRUD demo skipped: Vault is locked.")
        return

    # 1. CREATE: Save some new entries
    print("Saving new entries...")
    entry1 = {
        "name": "Google Account",
        "category": "Personal",
        "details": {
            "username": "my.email@gmail.com",
            "password": "generated_password_1",
            "url": "accounts.google.com",
            "notes": "Main personal account."
        }
    }
    entry2 = {
        "name": "Work GitHub",
        "category": "Work",
        "details": {
            "username": "work_user",
            "password": "generated_password_2",
            "url": "github.com",
            "notes": "Company GitHub account."
        }
    }
    id1 = vault.save_entry(entry1)
    id2 = vault.save_entry(entry2)
    print(f"✅ Saved 'Google' (ID: {id1}) and 'GitHub' (ID: {id2}).")

    # 2. READ: Get all entries
    all_entries = vault.get_all_entries()
    print(f"\nFound {len(all_entries)} entries in the vault:")
    for entry in all_entries:
        print(f"  - ID: {entry['id']}, Name: {entry['name']}, Category: {entry['category']}")

    # 3. UPDATE: Change the password for the Google account
    print("\nUpdating Google Account password...")
    google_entry_to_update = next((e for e in all_entries if e['id'] == id1), None)
    if google_entry_to_update:
        google_entry_to_update['details']['password'] = "a_new_updated_password_3"
        vault.save_entry(google_entry_to_update) # Saving with an existing 'id' performs an update
        print("✅ Password updated.")
        
        # Verify the update
        updated_entries = vault.get_all_entries()
        updated_google_entry = next((e for e in updated_entries if e['id'] == id1), None)
        print(f"  - Verified new password: '{updated_google_entry['details']['password']}'")

    # 4. DELETE: Remove the GitHub entry
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

    # 1. Attempt with incorrect old password
    print("Attempting to change password with INCORRECT old password...")
    try:
        vault.change_master_password("wrong-old-password", NEW_MASTER_PASSWORD)
    except IncorrectPasswordError:
        print("✅ Correctly caught 'IncorrectPasswordError'.")

    # 2. Perform a correct password change
    print("\nChanging master password correctly...")
    vault.change_master_password(MASTER_PASSWORD, NEW_MASTER_PASSWORD)
    print("✅ Master password changed successfully. All data has been re-encrypted.")

    # 3. VERY IMPORTANT: Verify the change
    print("Verifying the change...")
    vault.lock()
    print("  - Vault locked.")
    
    # a. Try unlocking with the OLD password (should fail)
    print("  - Attempting to unlock with OLD password...")
    try:
        vault.unlock(MASTER_PASSWORD)
    except IncorrectPasswordError:
        print("  - ✅ Correctly failed as expected.")

    # b. Unlock with the NEW password (should succeed)
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

    # 2. Export to encrypted .skey format (for secure backup)
    print(f"Exporting to secure .skey format at '{EXPORT_FILE_PATH}'...")
    
    # For secure export, we need the salt and an encryption function
    salt = vault._crypto.get_salt()
    encrypt_func = vault._crypto.encrypt
    
    if salt:
        encrypted_content = data_formats.export_to_encrypted_json(entries, salt, encrypt_func)
        with open(EXPORT_FILE_PATH, "wb") as f:
            f.write(encrypted_content)
        print("✅ Secure backup file created.")
    else:
        print("❌ Could not get salt for export.")
        return

    # 3. Import from the encrypted .skey file (simulating a restore)
    print(f"\nImporting from '{EXPORT_FILE_PATH}'...")
    try:
        with open(EXPORT_FILE_PATH, "rb") as f:
            file_bytes = f.read()

        # To import, we need to derive the correct key from the password and the salt IN THE FILE
        payload = json.loads(file_bytes)
        import_salt = base64.b64decode(payload['salt'])
        
        # Derive the key using the same method as the library
        # NOTE: We use the NEW master password because we changed it in the previous step
        derived_key = CryptoHandler._derive_key(NEW_MASTER_PASSWORD, import_salt)
        fernet = Fernet(derived_key)
        
        # Now, provide the decrypt function to the importer
        imported_entries = data_formats.import_from_encrypted_json(file_bytes, fernet.decrypt)
        
        print(f"✅ Successfully decrypted and imported {len(imported_entries)} entries:")
        for entry in imported_entries:
            print(f"  - Imported: {entry['name']}")

    except Exception as e:
        print(f"❌ Import failed: {e}")


def demonstrate_destruction(vault: Vault):
    """
    Shows the IRREVERSIBLE process of destroying a vault.
    """
    print("\n--- 5. VAULT DESTRUCTION DEMO ---")
    print("⚠️ WARNING: This action is IRREVERSIBLE and will securely delete all vault data.")
    
    # In a real app, you would use a GUI confirmation. Here we simulate it.
    # To run this part, uncomment the following lines.
    # confirm = input("Type 'DELETE' to confirm vault destruction: ")
    # if confirm == "DELETE":
    #     print("Destroying vault...")
    #     vault.destroy_vault()
    #     print("✅ Vault has been securely destroyed.")
    #     assert not os.path.exists(DATA_DIRECTORY)
    # else:
    #     print("Destruction cancelled.")
    print("Destruction demo is commented out for safety. To run, edit the script.")


def main():
    """
    Main function to run all demonstrations.
    """
    # Clean up from previous runs for a fresh start
    if os.path.exists(DATA_DIRECTORY):
        shutil.rmtree(DATA_DIRECTORY)
    if os.path.exists(EXPORT_FILE_PATH):
        os.remove(EXPORT_FILE_PATH)
        
    vault = None
    try:
        # Step 1: Setup and initial unlock
        vault = demonstrate_setup_and_unlock()

        # Step 2: Perform data operations
        demonstrate_crud_operations(vault)
        
        # Step 3: Change master password
        demonstrate_password_change(vault)

        # Step 4: Export and Import data
        demonstrate_export_import(vault)

        # Step 5: (Optional) Destroy the vault
        demonstrate_destruction(vault)

    except Exception as e:
        print(f"\n💥 An unexpected critical error occurred: {e}")
    finally:
        # The MOST IMPORTANT step: always ensure the vault is locked when done.
        if vault and vault.is_unlocked:
            vault.lock()
            print("\n--- FINALIZATION ---")
            print("✅ Vault has been locked to ensure data safety.")


if __name__ == "__main__":
    main()