# src/oracipher/data_formats.py

import csv
import io
import json
import logging
import re
import base64
import os
from typing import List, Dict, Any, Optional, Callable

# [修改] 导入注册表而不是单个模块
from .importers import importer_registry
from .exceptions import InvalidFileFormatError, OracipherError

logger = logging.getLogger(__name__)

# KEY_MAP remains the same, used for generic parsing
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

# --- 导出函数 (无变化) --- #

def export_to_encrypted_json(
    entries: List[Dict[str, Any]],
    salt: bytes,
    encrypt_func: Callable[[str], str]
) -> bytes:
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

# --- 导入函数 --- #

def import_from_encrypted_json(
    file_content_bytes: bytes,
    decrypt_func: Callable[[str], str]
) -> List[Dict[str, Any]]:
    # (无变化)
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
        raise InvalidFileFormatError("Incorrect password or corrupt file.") from e

def _parse_generic_csv(reader: csv.DictReader) -> List[Dict[str, Any]]:
    # (无变化)
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
        safe_row = {k.lower().strip() if k else '': v for k, v in row.items()}
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
    # (无变化)
    pass 

def _parse_key_colon_value_format(content: str) -> List[Dict[str, Any]]:
    # (无变化)
    pass

def _parse_double_slash_format(content: str) -> List[Dict[str, Any]]:
    # (无变化)
    pass

# --- [核心修改] 重构后的导入分发器 --- #
def import_from_file(
    file_path: str, file_content_bytes: bytes, password: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    High-level import dispatcher that detects file type and calls the appropriate parser.
    """
    file_ext = os.path.splitext(file_path)[1].lower()
    logger.info(f"Starting import from file with extension '{file_ext}': {os.path.basename(file_path)}")

    # 1. 动态查找合适的导入器
    for importer in importer_registry:
        if importer.can_handle(file_path, file_content_bytes):
            logger.info(f"Found suitable importer: '{importer.name}'")
            try:
                return importer.parse(file_content_bytes, password)
            except (ValueError, InvalidFileFormatError) as e:
                logger.warning(f"Import failed for {os.path.basename(file_path)} with {importer.name}: {e}")
                raise
            except Exception as e:
                logger.error(f"An unexpected error occurred processing file with {importer.name}: {e}", exc_info=True)
                raise OracipherError(f"Failed to process file: {e}") from e

    # 2. 如果没有找到特定导入器，则回退到通用解析器
    try:
        content_str = file_content_bytes.decode("utf-8-sig")
        if file_ext == ".csv":
            logger.info("No specific CSV format detected, falling back to generic parser.")
            dict_reader = csv.DictReader(io.StringIO(content_str))
            return _parse_generic_csv(dict_reader)
        elif file_ext in (".txt", ".md"):
            logger.info("Falling back to generic text parser.")
            return _parse_text_content(content_str)
    except Exception as e:
        logger.error(f"An unexpected error occurred during fallback parsing: {e}", exc_info=True)
        raise OracipherError(f"Failed to process file with fallback parser: {e}") from e

    # 3. 如果所有方法都失败
    raise InvalidFileFormatError(f"Unsupported file format for import: {file_ext}")