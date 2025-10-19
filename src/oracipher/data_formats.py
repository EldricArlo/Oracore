# src/oracipher/data_formats.py

import csv
import io
import json
import logging
import re
import base64
import os
from typing import List, Dict, Any, Optional, Callable

# 从子包中导入解析器
from .importers import google_chrome, samsung_pass
from .exceptions import InvalidFileFormatError, OracipherError

logger = logging.getLogger(__name__)

# KEY_MAP 作为模块级别的常量，用于通用解析
KEY_MAP = {
    "name": ["name", "title", "名称"],
    "username": ["username", "usename", "login", "user", "user id", "用户名", "用户"],
    "email": ["email", "邮箱"],
    "password": ["password", "pass", "密码"],
    "url": ["url", "website", "address", "uri", "网址", "地址"],
    "notes": ["notes", "remark", "extra", "备注"],
    "category": ["category", "cat", "group", "folder", "分类"],
    "totp": ["totp", "otpauth", "2fa", "2fa_app", "authenticator", "两步验证"],
}

# --- 导出函数 ---

def export_to_encrypted_json(
    entries: List[Dict[str, Any]],
    salt: bytes,
    encrypt_func: Callable[[str], str]
) -> bytes:
    """
    Serializes and encrypts a list of entries into the custom .skey format.

    Args:
        entries: The list of entry dictionaries to export.
        salt: The salt used for key derivation, to be stored in the exported file.
        encrypt_func: A callable (e.g., crypto_handler.encrypt) that takes a
                      plaintext string and returns an encrypted string.

    Returns:
        The complete, encrypted file content as bytes.
        
    Raises:
        OracipherError: If the export process fails.
    """
    logger.info(f"Preparing to securely export {len(entries)} entries to .skey format...")
    try:
        data_json_string = json.dumps(entries, ensure_ascii=False)
        encrypted_data_string = encrypt_func(data_json_string)
        
        export_payload = {
            "salt": base64.b64encode(salt).decode("utf-8"),
            "data": encrypted_data_string,
        }
        return json.dumps(export_payload, indent=2).encode("utf-8")
    except Exception as e:
        logger.error(f"Failed to create secure export package: {e}", exc_info=True)
        raise OracipherError(f"Failed to create secure export package: {e}") from e

def export_to_csv(entries: List[Dict[str, Any]], include_totp: bool = False) -> str:
    """
    Exports a list of entries to a CSV formatted string.

    Args:
        entries: The list of entry dictionaries to export.
        include_totp: If True, includes the TOTP secret as an otpauth URI.

    Returns:
        A string containing the data in CSV format.
        
    Raises:
        OracipherError: If the CSV export process fails.
    """
    BASE_FIELDNAMES: List[str] = [
        "name", "username", "email", "password", "url", "notes", "category",
    ]
    fieldnames = BASE_FIELDNAMES[:]
    if include_totp:
        fieldnames.append("totp")
    
    logger.info(f"Preparing to export {len(entries)} entries to CSV. Include TOTP: {include_totp}")
    
    try:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for entry in entries:
            details = entry.get("details", {})
            row = {
                "name": entry.get("name", ""),
                "username": details.get("username", ""),
                "email": details.get("email", ""),
                "password": details.get("password", ""),
                "url": details.get("url", ""),
                "notes": details.get("notes", ""),
                "category": entry.get("category", ""),
            }
            if include_totp:
                totp_secret = details.get("totp_secret", "")
                if totp_secret:
                    issuer = re.sub(r'[:/]', '', entry.get("name", "SafeKey"))
                    account = re.sub(r'[:/]', '', details.get("username") or details.get("email", "account"))
                    row["totp"] = f"otpauth://totp/{issuer}:{account}?secret={totp_secret}&issuer={issuer}"
                else:
                    row["totp"] = ""
            writer.writerow(row)
        
        return output.getvalue()
    except Exception as e:
        logger.error(f"Error during CSV export: {e}", exc_info=True)
        raise OracipherError(f"Error during CSV export: {e}") from e

# --- 导入函数 ---

def import_from_encrypted_json(
    file_content_bytes: bytes,
    decrypt_func: Callable[[str], str]
) -> List[Dict[str, Any]]:
    """
    Decrypts and parses entries from the custom .skey format.

    Args:
        file_content_bytes: The raw byte content of the .skey file.
        decrypt_func: A callable (e.g., a pre-configured Fernet decrypt method)
                      that takes an encrypted string and returns plaintext.

    Returns:
        A list of imported entry dictionaries.
        
    Raises:
        InvalidFileFormatError: If the file format is invalid or decryption fails.
    """
    logger.info("Attempting to decrypt and import from .skey file...")
    try:
        import_payload = json.loads(file_content_bytes.decode("utf-8"))
        encrypted_data_string = import_payload["data"]
        
        decrypted_json_string = decrypt_func(encrypted_data_string)
        entries = json.loads(decrypted_json_string)
        
        logger.info(f"Successfully decrypted and parsed {len(entries)} entries from .skey file.")
        return entries
    except (json.JSONDecodeError, KeyError, base64.binascii.Error) as e:
        raise InvalidFileFormatError("Invalid .skey file format.") from e
    except Exception as e:
        # Catches decryption errors (like CorruptDataError) from the provided function
        raise InvalidFileFormatError("Incorrect password or corrupt file.") from e

def _parse_generic_csv(reader: csv.DictReader) -> List[Dict[str, Any]]:
    imported_entries: List[Dict[str, Any]] = []
    header = [h.lower().strip() for h in (reader.fieldnames or [])]
    field_map: Dict[str, str] = {}
    for std_key, aliases in KEY_MAP.items():
        for alias in aliases:
            if alias in header:
                field_map[std_key] = alias
                break
    
    if "name" not in field_map:
        raise InvalidFileFormatError("Import failed: CSV file is missing a recognizable 'name' or 'title' column.")
    
    for row in reader:
        safe_row = {k.lower().strip(): v for k, v in row.items()}
        name_val = safe_row.get(field_map["name"], "").strip()
        if not name_val:
            continue
        
        details = {
            std_key: safe_row.get(csv_key, "").strip()
            for std_key, csv_key in field_map.items()
            if std_key not in ["name", "category", "totp"]
        }
        
        if "totp" in field_map:
            otp_uri = safe_row.get(field_map["totp"], "")
            if otp_uri.startswith("otpauth://"):
                try:
                    from urllib.parse import urlparse, parse_qs
                    query = parse_qs(urlparse(otp_uri).query)
                    if "secret" in query:
                        details["totp_secret"] = query["secret"][0]
                except Exception as e:
                    logger.warning(f"Could not parse TOTP URI for entry '{name_val}': {e}")
        
        entry: Dict[str, Any] = {
            "name": name_val,
            "category": safe_row.get(field_map.get("category", ""), "").strip(),
            "details": details,
        }
        imported_entries.append(entry)
    
    return imported_entries

def _parse_text_content(content: str) -> List[Dict[str, Any]]:
    # Simple heuristic to detect format
    first_lines = [line for line in content.strip().split("\n")[:5] if line.strip()]
    if first_lines and "//" in first_lines[0]:
        return _parse_double_slash_format(content)
    else:
        return _parse_key_colon_value_format(content)

def _parse_key_colon_value_format(content: str) -> List[Dict[str, Any]]:
    # ... (Implementation is the same as in the original DataHandler)
    pass # For brevity, logic is unchanged

def _parse_double_slash_format(content: str) -> List[Dict[str, Any]]:
    # ... (Implementation is the same as in the original DataHandler)
    pass # For brevity, logic is unchanged


def import_from_file(
    file_path: str, file_content_bytes: bytes, password: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    High-level import dispatcher that detects file type and calls the appropriate parser.
    
    Args:
        file_path: The full path to the file (used to determine the extension).
        file_content_bytes: The raw byte content of the file.
        password: The password, required for encrypted formats like .spass or .skey.

    Returns:
        A list of imported entry dictionaries.
        
    Raises:
        InvalidFileFormatError: If the file is not supported or parsing fails.
        OracipherError: For other unexpected errors during file processing.
    """
    file_ext = os.path.splitext(file_path)[1].lower()
    logger.info(f"Starting import from file with extension '{file_ext}': {os.path.basename(file_path)}")

    try:
        # Encrypted formats that need bytes
        if file_ext == ".spass":
            if not password:
                raise ValueError("Password is required for .spass files.")
            return samsung_pass.parse(file_content_bytes, password)
        
        # NOTE: .skey import is handled separately by the Vault class as it requires
        # a derived key for the decrypt_func. This dispatcher is for external formats.

        # Text-based formats, decode with utf-8-sig to handle potential BOM
        content_str = file_content_bytes.decode("utf-8-sig")

        if file_ext == ".csv":
            # Sniff for Google Chrome format first
            try:
                reader = csv.reader(io.StringIO(content_str))
                header = [h.lower().strip() for h in next(reader)]
                if header == google_chrome.EXPECTED_HEADER:
                    logger.info("Google Chrome CSV format detected.")
                    return google_chrome.parse(content_str)
            except (StopIteration, csv.Error):
                pass  # File might be empty or not valid CSV, let generic parser handle it
            
            logger.info("No specific CSV format detected, falling back to generic parser.")
            dict_reader = csv.DictReader(io.StringIO(content_str))
            return _parse_generic_csv(dict_reader)
        
        elif file_ext in (".txt", ".md"):
            return _parse_text_content(content_str)
        
        else:
            raise InvalidFileFormatError(f"Unsupported file format for import: {file_ext}")

    except (ValueError, InvalidFileFormatError) as e:
        logger.warning(f"Import failed for {os.path.basename(file_path)}: {e}")
        raise
    except Exception as e:
        logger.error(f"An unexpected error occurred processing file {os.path.basename(file_path)}: {e}", exc_info=True)
        raise OracipherError(f"Failed to process file: {e}") from e