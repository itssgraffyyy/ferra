"""BPF capture-filter validation.

Capture filters end up as an argument of ``tcpdump``/``dumpcap``.  They are
passed as an argument array (never through a shell), so command injection is
not possible - but a filter is still user input that can make a capture fail
or silently hide the traffic an experiment claims to contain.  Filters are
therefore restricted to a conservative character set and rejected otherwise.
"""

from __future__ import annotations

import re

from ..common.errors import ConfigValidationError

#: Characters allowed in a capture filter expression.
SAFE_FILTER_PATTERN = re.compile(r"^[A-Za-z0-9_.:/\[\]\s()!&|<>=+-]*$")
#: Maximum length of a capture filter.
MAX_FILTER_LENGTH = 512
#: Sequences that must never appear in a filter.
FORBIDDEN_SUBSTRINGS = (";", "`", "$", "\n", "\r", "\\", "'", '"', "..")


def validate_bpf_filter(expression: str) -> str:
    """Validate a BPF filter expression and return it unchanged.

    Raises :class:`ConfigValidationError` when the expression is empty, too
    long, contains shell metacharacters or unexpectedly unusual characters.
    The validation is intentionally conservative: filters are documented
    examples, not free-form user scripts.
    """
    if not isinstance(expression, str):
        raise ConfigValidationError(
            "capture filter must be a string",
            details={"got": type(expression).__name__},
        )
    text = expression.strip()
    if not text:
        raise ConfigValidationError("capture filter must not be empty")
    if len(text) > MAX_FILTER_LENGTH:
        raise ConfigValidationError(
            f"capture filter is too long ({len(text)} characters, max {MAX_FILTER_LENGTH})"
        )
    for forbidden in FORBIDDEN_SUBSTRINGS:
        if forbidden in text:
            raise ConfigValidationError(
                f"capture filter contains a forbidden character sequence: {forbidden!r}",
                hint="use plain BPF syntax, e.g. 'esp or (udp port 500) or icmp'",
                details={"filter": text, "forbidden": forbidden},
            )
    if not SAFE_FILTER_PATTERN.match(text):
        raise ConfigValidationError(
            "capture filter contains unsupported characters",
            hint="allowed characters: letters, digits, _ . : / [ ] whitespace ( ) ! & | < > = + -",
            details={"filter": text},
        )
    return text


def default_capture_filter(
    *,
    ike_port: int = 500,
    nat_t_port: int = 4500,
    ip_version: int = 4,
    include_icmp: bool = True,
) -> str:
    """Return the default filter: IKE + ESP (+ ICMP) for one IP version.

    The default is deliberately *narrow but sufficient* for dataset sanity
    checks: it keeps IKE negotiation, ESP payloads and the ICMP traffic of the
    baseline experiment, while ignoring unrelated host traffic such as
    neighbour discovery noise.
    """
    parts: list[str] = []
    if ip_version == 4:
        parts.append(f"(udp port {ike_port} or udp port {nat_t_port})")
        parts.append("esp")
        if include_icmp:
            parts.append("icmp")
    else:
        parts.append(f"(udp port {ike_port} or udp port {nat_t_port})")
        parts.append("esp")
        if include_icmp:
            parts.append("ip6 proto 58")
    return " or ".join(parts)


__all__ = ["FORBIDDEN_SUBSTRINGS", "MAX_FILTER_LENGTH", "SAFE_FILTER_PATTERN", "default_capture_filter", "validate_bpf_filter"]
