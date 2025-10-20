# src/oracipher/importers/google_chrome.py

import csv
import io
import logging
from typing import List, Dict, Any

from ..exceptions import InvalidFileFormatError

logger = logging.getLogger(__name__)

# 定义为模块常量，方便外部模块引用和验证
EXPECTED_HEADER = ["name", "url", "username", "password"]

def parse(file_content: str) -> List[Dict[str, Any]]:
    """
    Parses the content of a CSV file exported from Google Chrome / Google Passwords.

    Args:
        file_content: The string content of the CSV file.

    Returns:
        A list of dictionaries, where each dictionary represents an imported entry.

    Raises:
        InvalidFileFormatError: If the CSV header does not match the expected
                                Google Chrome format.
    """
    logger.info("Attempting to parse file using Google Chrome importer...")
    imported_entries: List[Dict[str, Any]] = []
    
    try:
        # Use io.StringIO to treat the string content like a file
        f = io.StringIO(file_content)
        reader = csv.DictReader(f)

        # 验证CSV表头是否符合预期格式
        if not reader.fieldnames or [h.lower().strip() for h in reader.fieldnames] != EXPECTED_HEADER:
            logger.error("CSV header mismatch. Expected: %s, Got: %s", EXPECTED_HEADER, reader.fieldnames)
            raise InvalidFileFormatError("CSV header does not match the expected Google Chrome format.")

        for row in reader:
            # 条目的 'name' 字段是必需的，如果为空则跳过该行
            name = row.get("name", "").strip()
            if not name:
                continue

            # 构建符合 oracipher 内部数据结构的字典
            entry: Dict[str, Any] = {
                "name": name,
                "category": "",  # Google 导出的数据没有分类信息，默认为空
                "details": {
                    "username": row.get("username", "").strip(),
                    "password": row.get("password", ""), # 密码保持原样，不 strip()
                    "url": row.get("url", "").strip(),
                    "notes": "", # Google 导出的数据没有备注字段
                },
            }
            imported_entries.append(entry)

        logger.info(
            f"Successfully parsed {len(imported_entries)} entries with Google Chrome importer."
        )
        return imported_entries

    except csv.Error as e:
        # 捕获CSV解析过程中的错误
        logger.error("Failed to parse CSV content: %s", e, exc_info=True)
        raise InvalidFileFormatError(f"Failed to parse CSV file: {e}") from e
    except Exception as e:
        # 捕获其他意外错误
        logger.error("An unexpected error occurred in Google Chrome importer: %s", e, exc_info=True)
        # 重新抛出，避免隐藏原始错误
        raise