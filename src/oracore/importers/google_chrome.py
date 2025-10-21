# src/oracipher/importers/google_chrome.py

import csv
import io
import logging
import os
from typing import List, Dict, Any, Optional

from ..exceptions import InvalidFileFormatError
from .base import BaseImporter

logger = logging.getLogger(__name__)

EXPECTED_HEADER = ["name", "url", "username", "password"]

class GoogleChromeImporter(BaseImporter):
    """Importer for CSV files exported from Google Chrome / Google Passwords."""

    @property
    def name(self) -> str:
        return "Google Chrome CSV"

    def can_handle(
        self, file_path: str, file_content_bytes: Optional[bytes] = None
    ) -> bool:
        if not file_path.lower().endswith(".csv"):
            return False
        
        if file_content_bytes is None:
            # If content is not provided, we rely on extension only.
            # In the main dispatcher, we'd ensure content is passed for CSVs.
            return True

        try:
            content_str = file_content_bytes.decode("utf-8-sig")
            reader = csv.reader(io.StringIO(content_str))
            header = [h.lower().strip() for h in next(reader)]
            return header == EXPECTED_HEADER
        except (StopIteration, csv.Error, UnicodeDecodeError):
            return False

    def parse(
        self, file_content_bytes: bytes, password: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        logger.info(f"Attempting to parse file using {self.name} importer...")
        imported_entries: List[Dict[str, Any]] = []
        
        try:
            content_str = file_content_bytes.decode("utf-8-sig")
            f = io.StringIO(content_str)
            reader = csv.DictReader(f)

            if not reader.fieldnames or [h.lower().strip() for h in reader.fieldnames] != EXPECTED_HEADER:
                logger.error("CSV header mismatch. Expected: %s, Got: %s", EXPECTED_HEADER, reader.fieldnames)
                raise InvalidFileFormatError("CSV header does not match the expected Google Chrome format.")

            for row in reader:
                name = row.get("name", "").strip()
                if not name:
                    continue

                entry: Dict[str, Any] = {
                    "name": name,
                    "category": "",
                    "details": {
                        "username": row.get("username", "").strip(),
                        "password": row.get("password", ""),
                        "url": row.get("url", "").strip(),
                        "notes": "",
                    },
                }
                imported_entries.append(entry)

            logger.info(
                f"Successfully parsed {len(imported_entries)} entries with {self.name} importer."
            )
            return imported_entries

        except csv.Error as e:
            logger.error("Failed to parse CSV content: %s", e, exc_info=True)
            raise InvalidFileFormatError(f"Failed to parse CSV file: {e}") from e
        except Exception as e:
            logger.error(f"An unexpected error occurred in {self.name} importer: %s", e, exc_info=True)
            raise