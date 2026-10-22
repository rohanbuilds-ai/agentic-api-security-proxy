"""Deterministic Request Inspection, Input Validation, and Adversarial Text Detection.

SECURITY ARCHITECTURE NOTE:
- Strictly deterministic heuristics and bounds checking.
- Defense-in-depth: Heuristic text detection does NOT replace authentication, RBAC,
  or tenant isolation. It operates as an ingress filter to drop overtly adversarial payloads.
- Rejection responses are standardized and machine-readable with a stable rule_id.
- Designed to minimize false positives on normal business text.
"""
import re
from typing import Any, Dict, List, Optional, Tuple
from src.schemas.action import ActionType, AgentActionRequest

# Payload and parameter boundary limits
MAX_PAYLOAD_SIZE_BYTES = 64 * 1024  # 64 KB
MAX_CUSTOMER_NAME_LEN = 100
MAX_ITEM_NAME_LEN = 100
MAX_NOTES_LEN = 500
MAX_QUANTITY = 1000
MAX_TOTAL_PRICE = 100000.0


class InputValidationError(Exception):
    """Raised when request parameters violate schema boundaries, length limits, or ranges."""
    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.status_code = 400
        self.error_code = "ERR_INPUT_VALIDATION"
        self.detail = detail


class AdversarialInputError(Exception):
    """Raised when an ingress request contains high-confidence adversarial instruction patterns."""
    def __init__(self, rule_id: str, detail: str) -> None:
        super().__init__(detail)
        self.status_code = 403
        self.error_code = "ERR_INPUT_POLICY"
        self.rule_id = rule_id
        self.detail = detail


# Configurable, deterministic adversarial pattern rules
ADVERSARIAL_RULES: List[Tuple[str, re.Pattern[str], str]] = [
    (
        "INPUT_INSTRUCTION_OVERRIDE",
        re.compile(
            r"(?i)\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|directives|prompts|safeguards)\b"
        ),
        "Attempt to override or disregard prior instructions detected.",
    ),
    (
        "INPUT_INSTRUCTION_OVERRIDE",
        re.compile(
            r"(?i)\b(?:system\s+override|developer\s+mode\s+(?:override|enable|activated?)|you\s+are\s+now\s+(?:in\s+)?(?:developer|unrestricted|dan|jailbreak)\s+mode)\b"
        ),
        "System override or developer jailbreak prompt detected.",
    ),
    (
        "INPUT_SECURITY_BYPASS",
        re.compile(
            r"(?i)\b(?:disable|bypass|deactivate|turn\s+off)\s+(?:all\s+)?(?:security|safety|auth[a-z]*|guardrails?|controls?|filters?|safeguards?)\b"
        ),
        "Explicit attempt to disable or bypass security safeguards detected.",
    ),
    (
        "INPUT_DATA_EXFILTRATION",
        re.compile(
            r"(?i)\b(?:dump|exfiltrate|leak|reveal|print|return)\s+(?:all\s+)?(?:other\s+tenants?|api[_-]?keys?|passwords?|credentials?|secrets?|private\s+data)\b"
        ),
        "Attempt to exfiltrate private credentials, secrets, or other tenants' data detected.",
    ),
    (
        "INPUT_DATA_EXFILTRATION",
        re.compile(
            r"(?i)\bshow\s+(?:me\s+)?(?:all\s+)?(?:other\s+tenants?|system\s+secrets?|database\s+passwords?|internal\s+credentials?)\b"
        ),
        "Attempt to inspect internal system secrets or cross-tenant databases detected.",
    ),
]


class RequestSanitizer:
    """Inspects action requests for boundary violations and adversarial instruction patterns."""

    def __init__(self) -> None:
        self.rules = ADVERSARIAL_RULES

    def scan_text(self, text: str) -> Optional[Tuple[str, str]]:
        """Scan a single text string against configured heuristic rules.

        Returns (rule_id, detail) on first high-confidence match, or None if safe.
        """
        if not text or not isinstance(text, str):
            return None

        for rule_id, pattern, detail in self.rules:
            if pattern.search(text):
                return rule_id, detail

        return None

    def _extract_all_strings(self, data: Any) -> List[str]:
        """Recursively extract all string values from nested request structures."""
        results: List[str] = []
        if isinstance(data, str):
            results.append(data)
        elif isinstance(data, dict):
            for v in data.values():
                results.extend(self._extract_all_strings(v))
        elif isinstance(data, list):
            for item in data:
                results.extend(self._extract_all_strings(item))
        return results

    def inspect_request(
        self,
        request: AgentActionRequest,
        payload_bytes: Optional[int] = None,
    ) -> None:
        """Inspect the incoming request payload for parameter boundaries and adversarial patterns.

        Raises:
            InputValidationError: If parameters violate numerical bounds or length caps.
            AdversarialInputError: If high-confidence prompt injection or exfiltration patterns are detected.
        """
        # 1. Payload size check
        if payload_bytes is not None and payload_bytes > MAX_PAYLOAD_SIZE_BYTES:
            raise InputValidationError(
                f"Request payload size ({payload_bytes} bytes) exceeds maximum permitted limit ({MAX_PAYLOAD_SIZE_BYTES} bytes)."
            )

        # 2. Free-text adversarial inspection on resource_id
        if request.resource_id:
            match = self.scan_text(request.resource_id)
            if match:
                rule_id, detail = match
                raise AdversarialInputError(rule_id=rule_id, detail=detail)

        # 3. Parameter validation & inspection
        if request.parameters:
            # A. Parameter-specific limits for create_order
            if request.action == ActionType.CREATE_ORDER:
                params = request.parameters

                # Customer name bounds
                cust_name = params.get("customer_name")
                if not isinstance(cust_name, str) or len(cust_name.strip()) == 0:
                    raise InputValidationError("Field 'customer_name' must be a non-empty string.")
                if len(cust_name) > MAX_CUSTOMER_NAME_LEN:
                    raise InputValidationError(
                        f"Field 'customer_name' exceeds maximum length of {MAX_CUSTOMER_NAME_LEN} characters."
                    )

                # Item name bounds
                item = params.get("item")
                if not isinstance(item, str) or len(item.strip()) == 0:
                    raise InputValidationError("Field 'item' must be a non-empty string.")
                if len(item) > MAX_ITEM_NAME_LEN:
                    raise InputValidationError(
                        f"Field 'item' exceeds maximum length of {MAX_ITEM_NAME_LEN} characters."
                    )

                # Quantity bounds
                quantity = params.get("quantity")
                if not isinstance(quantity, int) or isinstance(quantity, bool):
                    raise InputValidationError("Field 'quantity' must be an integer.")
                if quantity <= 0 or quantity > MAX_QUANTITY:
                    raise InputValidationError(
                        f"Field 'quantity' must be between 1 and {MAX_QUANTITY}."
                    )

                # Price bounds
                price = params.get("total_price")
                if not isinstance(price, (int, float)) or isinstance(price, bool):
                    raise InputValidationError("Field 'total_price' must be a numeric value.")
                if price <= 0.0 or price > MAX_TOTAL_PRICE:
                    raise InputValidationError(
                        f"Field 'total_price' must be greater than 0.0 and at most {MAX_TOTAL_PRICE}."
                    )

                # Notes bounds
                notes = params.get("notes")
                if notes is not None:
                    if not isinstance(notes, str):
                        raise InputValidationError("Field 'notes' must be a string if provided.")
                    if len(notes) > MAX_NOTES_LEN:
                        raise InputValidationError(
                            f"Field 'notes' exceeds maximum length of {MAX_NOTES_LEN} characters."
                        )

            # B. Recursive adversarial text scan on all string parameters
            all_strings = self._extract_all_strings(request.parameters)
            for text in all_strings:
                match = self.scan_text(text)
                if match:
                    rule_id, detail = match
                    raise AdversarialInputError(rule_id=rule_id, detail=detail)


# Global singleton instance
request_sanitizer = RequestSanitizer()
