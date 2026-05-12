"""
core/parsers.py
---------------
Defines the parsing interfaces and concrete implementations for IaC files.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict

import hcl2
import yaml


class AbstractParser(ABC):
    """
    Abstract parser interface for all Infrastructure-as-Code parsers.
    Defines the common parsing contract.
    """

    @abstractmethod
    def parse(self, content: bytes) -> Dict[str, Any]:
        """
        Parse raw bytes into a Python dictionary.
        Raises ValueError if the content is invalid.
        """
        pass


def _normalize_hcl(data: Any) -> Any:
    """Recursively clean up extra quotes and backslashes added by python-hcl2."""
    if isinstance(data, dict):
        return {k: _normalize_hcl(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_normalize_hcl(v) for v in data]
    elif isinstance(data, str):
        # Remove surrounding quotes if they exist
        if (data.startswith('"') and data.endswith('"')) or (
            data.startswith("'") and data.endswith("'")
        ):
            data = data[1:-1]
        # Unescape escaped quotes
        data = data.replace('\\"', '"').replace("\\'", "'")
        return data
    return data


class TerraformParser(AbstractParser):
    """Parses Terraform (.tf) HCL files into a Python dictionary."""

    def parse(self, content: bytes) -> Dict[str, Any]:
        try:
            # Decode ignoring errors to avoid crash on binary data, though we expect text.
            decoded_content = content.decode("utf-8", errors="replace")
            parsed_data = hcl2.loads(decoded_content)
            # Normalize to clean up hcl2 artifacts (extra backslashes and quotes)
            return _normalize_hcl(parsed_data)
        except Exception as e:
            raise ValueError(f"Failed to parse Terraform file: {str(e)}")


class CloudFormationParser(AbstractParser):
    """Parses CloudFormation (.yaml or .json) files into a Python dictionary."""

    def parse(self, content: bytes) -> Dict[str, Any]:
        try:
            decoded_content = content.decode("utf-8", errors="replace")
            return yaml.safe_load(decoded_content)
        except Exception as e:
            raise ValueError(f"Failed to parse CloudFormation file: {str(e)}")


def get_parser(filename: str) -> AbstractParser:
    """Factory function to select the appropriate parser based on file extension."""
    if filename.endswith(".tf"):
        return TerraformParser()
    elif filename.endswith((".yaml", ".yml", ".json")):
        return CloudFormationParser()
    else:
        raise ValueError(f"Unsupported file type for {filename}")
