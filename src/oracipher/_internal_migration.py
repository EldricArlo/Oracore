# src/oracipher/_internal_migration.py

import os
import sqlite3
import logging

logger = logging.getLogger(__name__)

def check_and_migrate_schema(db_path: str) -> None:
    """
    [Internal Function] Checks for an old, incompatible database schema.

    If an old schema (identified by a UNIQUE constraint on entries.name)
    is detected, it backs up the old database file, allowing the application
    to create a new, empty, and compatible database.
    """
    if not os.path.exists(db_path):
        return  # Nothing to migrate if the database doesn't exist

    try:
        # Connect to the database to inspect its schema
        conn_check = sqlite3.connect(db_path)
        cursor_check = conn_check.cursor()

        # Query the schema information for the 'entries' table
        cursor_check.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='entries'"
        )
        result = cursor_check.fetchone()
        conn_check.close()

        if result:
            create_sql = result[0]
            # The signature of the old schema is a UNIQUE constraint in the CREATE statement.
            if "UNIQUE" in create_sql.upper():
                backup_path = db_path + ".backup_old_schema"
                logger.warning(
                    "Old database schema detected (with UNIQUE constraint on entries.name)."
                )
                logger.warning(f"Backing up old database to: {backup_path}")
                
                # Rename the existing file to create the backup
                os.rename(db_path, backup_path)
                
                logger.warning(
                    "Backup complete. A new, compatible database will be created on next connect."
                )
    except Exception as e:
        # If any error occurs during the check, log it but don't crash the app.
        logger.error(f"Error while checking database schema: {e}", exc_info=True)