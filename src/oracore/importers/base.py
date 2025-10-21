# src/oracipher/importers/base.py

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

class BaseImporter(ABC):
    """
    Abstract Base Class for all data importers.

    This defines a common interface that allows the import dispatcher
    to treat all importers uniformly (Strategy Pattern).
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the human-readable name of the importer."""
        pass

    @abstractmethod
    def can_handle(
        self, file_path: str, file_content_bytes: Optional[bytes] = None
    ) -> bool:
        """
        Determines if this importer can handle the given file.

        Args:
            file_path: The full path or name of the file.
            file_content_bytes: The raw byte content of the file, for sniffing.

        Returns:
            True if the importer can handle the file, False otherwise.
        """
        pass

    @abstractmethod
    def parse(
        self, file_content_bytes: bytes, password: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Parses the file content and returns a list of entry dictionaries.

        Args:
            file_content_bytes: The raw byte content of the file.
            password: An optional password for encrypted formats.

        Returns:
            A list of imported entry dictionaries.

        Raises:
            InvalidFileFormatError: If parsing fails.
        """
        pass