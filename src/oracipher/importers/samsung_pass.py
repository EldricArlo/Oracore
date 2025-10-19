# src/oracipher/importers/samsung_pass.py

import csv
import io
import logging
import base64
import hashlib
import re
from typing import List, Dict, Any

# [修改] 移除 pycryptodome 依赖，改用 cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from ..exceptions import InvalidFileFormatError

logger = logging.getLogger(__name__)

# 为三星Pass解密格式定义常量，提高可读性和可维护性
SAMSUNG_PASS_SALT_SIZE = 20
SAMSUNG_PASS_IV_SIZE = 16  # AES block size
SAMSUNG_PASS_PBKDF2_ITERATIONS = 70000
SAMSUNG_PASS_PBKDF2_KEY_LENGTH = 32
SAMSUNG_PASS_PBKDF2_DIGEST = "sha256"

def _clean_android_url(url: str) -> str:
    """
    Intelligently cleans a URL, preferring standard web URLs and converting
    only non-standard Android App Links.
    """
    if not url:
        return ""
    if re.search(r"\.[a-zA-Z]{2,}", url):
        return url
    
    if url.startswith("android://"):
        try:
            package_name = url.split("@")[-1]
            package_to_domain_map = {
                "com.anthropic.claude": "claude.ai",
                "com.google.android.gm": "mail.google.com",
                "com.facebook.katana": "facebook.com",
                "com.twitter.android": "twitter.com",
                "com.instagram.android": "instagram.com",
            }
            if package_name in package_to_domain_map:
                return package_to_domain_map[package_name]
            
            parts = package_name.split(".")
            if len(parts) >= 2 and "android" not in parts[-2]:
                return f"{parts[-2]}.{parts[-1]}"
            return package_name
        except Exception:
            return url
    return url

def _parse_decrypted_content(decrypted_content: str) -> List[Dict[str, Any]]:
    """Parses the decrypted, multi-block CSV-like content."""
    logger.info("Parsing the decrypted multi-block content...")
    
    blocks = decrypted_content.split("next_table")
    login_data_block = None
    
    expected_header_str = "_id;origin_url;action_url;username_element;username_value;id_tz_enc;password_element;password_value;pw_tz_enc;host_url;ssl_valid;preferred;blacklisted_by_user;use_additional_auth;cm_api_support;created_time;modified_time;title;favicon;source_type;app_name;package_name;package_signature;reserved_1;reserved_2;reserved_3;reserved_4;reserved_5;reserved_6;reserved_7;reserved_8;credential_memo;otp"
    
    for block in blocks:
        clean_block = block.strip()
        if clean_block.startswith(expected_header_str):
            login_data_block = clean_block
            break
            
    if not login_data_block:
        raise InvalidFileFormatError("Could not find the login data block in the decrypted content.")
        
    reader = csv.DictReader(io.StringIO(login_data_block), delimiter=";")
    imported_entries: List[Dict[str, Any]] = []

    for row in reader:
        if not row.get("title", "").strip():
            continue

        def decode_field(field_name: str) -> str:
            b64_string = row.get(field_name, "")
            if not b64_string or b64_string == "JiYmTlVMTCYmJg==":
                return ""
            try:
                missing_padding = len(b64_string) % 4
                if missing_padding:
                    b64_string += "=" * (4 - missing_padding)
                return base64.b64decode(b64_string).decode("utf-8")
            except Exception:
                return row.get(field_name, "")

        raw_url = decode_field("origin_url")
        cleaned_url = _clean_android_url(raw_url)
        
        entry: Dict[str, Any] = {
            "name": decode_field("title"),
            "category": "Samsung Pass",
            "details": {
                "username": decode_field("username_value"),
                "password": decode_field("password_value"),
                "url": cleaned_url,
                "notes": decode_field("credential_memo"),
            },
        }
        imported_entries.append(entry)
        
    return imported_entries

def parse(file_content_bytes: bytes, password: str) -> List[Dict[str, Any]]:
    """
    Decrypts and parses a Samsung Pass export file (.spass).
    """
    logger.info("Attempting to decrypt and parse Samsung Pass file...")
    try:
        base64_data = file_content_bytes.decode("utf-8").strip()
        binary_data = base64.b64decode(base64_data)

        salt = binary_data[:SAMSUNG_PASS_SALT_SIZE]
        iv_start = SAMSUNG_PASS_SALT_SIZE
        data_start = iv_start + SAMSUNG_PASS_IV_SIZE
        iv = binary_data[iv_start:data_start]
        encrypted_data = binary_data[data_start:]

        key = hashlib.pbkdf2_hmac(
            SAMSUNG_PASS_PBKDF2_DIGEST,
            password.encode("utf-8"),
            salt,
            SAMSUNG_PASS_PBKDF2_ITERATIONS,
            dklen=SAMSUNG_PASS_PBKDF2_KEY_LENGTH,
        )

        # [修改] 使用 cryptography 进行解密
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # [修改] 使用 cryptography 进行 PKCS7 unpadding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        final_content = decrypted_data.decode("utf-8")

        entries = _parse_decrypted_content(final_content)
        logger.info(f"Successfully decrypted and parsed {len(entries)} entries from Samsung Pass file.")
        return entries

    except (ValueError, KeyError, base64.binascii.Error) as e:
        logger.error(f"Decryption failed, likely an incorrect password or corrupt file. Details: {e}", exc_info=True)
        raise InvalidFileFormatError("Decryption failed. Please ensure the password is correct or the file is not corrupt.") from e
    except Exception as e:
        logger.error(f"An unexpected error occurred during Samsung Pass import: {e}", exc_info=True)
        raise InvalidFileFormatError(f"An unexpected error occurred during Samsung Pass import: {e}") from e