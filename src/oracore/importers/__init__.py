# src/oracipher/importers/__init__.py

from .base import BaseImporter
from .google_chrome import GoogleChromeImporter
from .samsung_pass import SamsungPassImporter

# The registry of all available importer instances.
# The dispatcher will iterate over this list to find a suitable importer.
importer_registry = [
    GoogleChromeImporter(),
    SamsungPassImporter(),
]

__all__ = ["BaseImporter", "importer_registry"]