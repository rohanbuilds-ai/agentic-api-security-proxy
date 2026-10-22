"""Outbound Data Loss Prevention (DLP) and Sensitive Data Redaction.

SECURITY ARCHITECTURE NOTE:
- Inspects upstream response payloads before returning them to client agents.
- Recursive inspection traverses nested JSON dictionaries, lists, and strings.
- Detects and masks:
  1. Synthetic US Social Security Numbers (SSNs).
  2. Credit card numbers (common 13-19 digit formats validated by Luhn algorithm).
  3. API key and Bearer token patterns.
  4. Synthetic development secrets.
- Fails closed: If inspection encounters an error, the uninspected payload is withheld.
- Sanitized metadata (redaction count and categories) is reported without leaking raw secrets.
"""
import re
from typing import Any, Dict, List, Optional, Set, Tuple


class DLPInspectionError(Exception):
    """Raised when egress response inspection fails (triggers fail-closed withholding)."""
    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.status_code = 502
        self.error_code = "ERR_DLP_FAILURE"
        self.detail = detail


# Regex pattern definitions
SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CREDIT_CARD_CANDIDATE_PATTERN = re.compile(r"\b(?:\d{4}[- ]?){3}\d{1,4}\b|\b\d{13,19}\b")
API_KEY_PATTERN = re.compile(
    r"\b(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|Bearer\s+[a-zA-Z0-9_\-\.]{20,}|api[_-]?key[_-]?[a-zA-Z0-9]{16,})\b",
    re.IGNORECASE,
)
SYNTHETIC_SECRET_PATTERN = re.compile(
    r"\b(?:SYNTHETIC_SECRET_[a-zA-Z0-9_]+|SECRET_KEY_[a-zA-Z0-9_]+)\b"
)


def is_luhn_valid(candidate: str) -> bool:
    """Validate numeric string using the Luhn checksum algorithm."""
    digits = [int(c) for c in candidate if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled if doubled < 10 else doubled - 9
        else:
            checksum += digit

    return checksum % 10 == 0


class DataLossPreventionEngine:
    """Outbound response scanner for detecting and masking sensitive data."""

    def redact_text(self, text: str) -> Tuple[str, int, Set[str]]:
        """Scan and redact sensitive patterns within a text string.

        Returns:
            Tuple of (sanitized_text, redaction_count, set_of_redacted_categories)
        """
        if not text or not isinstance(text, str):
            return text, 0, set()

        total_redactions = 0
        categories: Set[str] = set()

        # 1. Redact Synthetic SSNs
        def ssn_sub(match: re.Match[str]) -> str:
            nonlocal total_redactions
            total_redactions += 1
            categories.add("SSN")
            return "[REDACTED_SSN]"

        sanitized = SSN_PATTERN.sub(ssn_sub, text)

        # 2. Redact Credit Card Numbers (Validated by Luhn to reduce false positives)
        def cc_sub(match: re.Match[str]) -> str:
            nonlocal total_redactions
            raw_match = match.group(0)
            if is_luhn_valid(raw_match):
                total_redactions += 1
                categories.add("CREDIT_CARD")
                return "[REDACTED_CREDIT_CARD]"
            return raw_match

        sanitized = CREDIT_CARD_CANDIDATE_PATTERN.sub(cc_sub, sanitized)

        # 3. Redact API Keys / Bearer Tokens
        def api_key_sub(match: re.Match[str]) -> str:
            nonlocal total_redactions
            total_redactions += 1
            categories.add("API_KEY")
            return "[REDACTED_API_KEY]"

        sanitized = API_KEY_PATTERN.sub(api_key_sub, sanitized)

        # 4. Redact Synthetic Test Secrets
        def secret_sub(match: re.Match[str]) -> str:
            nonlocal total_redactions
            total_redactions += 1
            categories.add("SYNTHETIC_SECRET")
            return "[REDACTED_SECRET]"

        sanitized = SYNTHETIC_SECRET_PATTERN.sub(secret_sub, sanitized)

        return sanitized, total_redactions, categories

    def _traverse_and_redact(self, data: Any) -> Tuple[Any, int, Set[str]]:
        """Recursively traverse arbitrary JSON data structures (dict, list, str, primitives)."""
        if data is None:
            return None, 0, set()

        if isinstance(data, str):
            return self.redact_text(data)

        if isinstance(data, dict):
            redacted_dict: Dict[str, Any] = {}
            total_count = 0
            all_categories: Set[str] = set()
            for key, value in data.items():
                # Keys are preserved as-is; values are recursively redacted
                redacted_val, count, cats = self._traverse_and_redact(value)
                redacted_dict[key] = redacted_val
                total_count += count
                all_categories.update(cats)
            return redacted_dict, total_count, all_categories

        if isinstance(data, list):
            redacted_list: List[Any] = []
            total_count = 0
            all_categories: Set[str] = set()
            for item in data:
                redacted_item, count, cats = self._traverse_and_redact(item)
                redacted_list.append(redacted_item)
                total_count += count
                all_categories.update(cats)
            return redacted_list, total_count, all_categories

        # Numeric, boolean, and other primitives remain unmodified
        return data, 0, set()

    def inspect_and_redact(self, payload: Any) -> Tuple[Any, Optional[Dict[str, Any]]]:
        """Inspect and sanitize an upstream payload prior to egress.

        Returns:
            Tuple of (sanitized_payload, redaction_metadata_or_None)

        Raises:
            DLPInspectionError: On unexpected parsing failure, enforcing fail-closed withholding.
        """
        try:
            sanitized_data, count, categories = self._traverse_and_redact(payload)
            metadata = None
            if count > 0:
                metadata = {
                    "count": count,
                    "categories": sorted(list(categories)),
                }
            return sanitized_data, metadata
        except Exception as e:
            # Fail closed: Do NOT leak raw upstream response on inspection error
            raise DLPInspectionError(
                "Response inspection failed during sensitive data sanitization; payload withheld for safety."
            ) from e


# Global singleton instance
dlp_engine = DataLossPreventionEngine()
