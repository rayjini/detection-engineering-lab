"""Offline Sigma rule evaluator.

Evaluates a Sigma rule against a single log event (a flat dict using Sigma /
Sysmon field names, e.g. ``Image``, ``CommandLine``) so rules can be unit-tested
against curated sample logs without a SIEM.

pySigma parses the rule (modifiers, wildcards, ``1 of``/``all of`` etc. are all
resolved by pySigma itself); this module only walks the resulting condition tree
and compares values. Matching follows Sigma semantics: string comparison is
case-insensitive unless the ``cased`` modifier is used.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any, Mapping

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionIdentifier,
    ConditionNOT,
    ConditionOR,
    ConditionSelector,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

_MISSING = object()

_REGEX_FLAGS = {
    SigmaRegularExpressionFlag.IGNORECASE: re.IGNORECASE,
    SigmaRegularExpressionFlag.MULTILINE: re.MULTILINE,
    SigmaRegularExpressionFlag.DOTALL: re.DOTALL,
}


class UnsupportedSigmaFeature(Exception):
    """Raised when a rule uses a construct this evaluator cannot test offline."""


def load_rule(path: str | Path) -> SigmaRule:
    return SigmaRule.from_yaml(Path(path).read_text(encoding="utf-8"))


def matches(rule: SigmaRule, event: Mapping[str, Any]) -> bool:
    """Return True if ``event`` satisfies any of the rule's conditions."""
    return any(_eval(cond.parse(), event) for cond in rule.detection.parsed_condition)


# --------------------------------------------------------------------------- #
# Condition tree
# --------------------------------------------------------------------------- #
def _eval(node: Any, event: Mapping[str, Any]) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _field_matches(event, node.field, node.value)
    if isinstance(node, ConditionValueExpression):
        # Keyword search is full-text: the value may appear anywhere in any field.
        return any(_keyword_matches(v, node.value, event) for v in _iter_values(event))
    if isinstance(node, (ConditionIdentifier, ConditionSelector)):
        # Normally resolved away by pySigma's parse(); handled defensively.
        return all(_eval(a, event) for a in node.args)
    raise UnsupportedSigmaFeature(f"condition node {type(node).__name__}")


# --------------------------------------------------------------------------- #
# Field / value matching
# --------------------------------------------------------------------------- #
def _get_field(event: Mapping[str, Any], field: str) -> Any:
    if field in event:
        return event[field]
    lowered = field.lower()
    for key, val in event.items():  # Windows field names are case-insensitive in practice
        if key.lower() == lowered:
            return val
    return _MISSING


def _iter_values(event: Mapping[str, Any]):
    for key, val in event.items():
        if key.startswith("_"):  # metadata such as _comment is not log content
            continue
        if isinstance(val, list):
            yield from val
        else:
            yield val


def _keyword_matches(actual: Any, expected: Any, event: Mapping[str, Any]) -> bool:
    if isinstance(expected, SigmaExpansion):
        return any(_keyword_matches(actual, v, event) for v in expected.values)
    if isinstance(expected, SigmaString):
        return _string_regex(expected).search(_to_str(actual)) is not None
    return _value_matches(actual, expected, event)


def _field_matches(event: Mapping[str, Any], field: str, expected: Any) -> bool:
    actual = _get_field(event, field)

    if isinstance(expected, SigmaExists):
        return (actual is not _MISSING) == expected.exists
    if isinstance(expected, SigmaNull):
        return actual is _MISSING or actual is None or actual == ""
    if actual is _MISSING or actual is None:
        return False
    if isinstance(actual, list):
        return any(_value_matches(a, expected, event) for a in actual)
    return _value_matches(actual, expected, event)


def _value_matches(actual: Any, expected: Any, event: Mapping[str, Any]) -> bool:
    if isinstance(expected, SigmaExpansion):
        return any(_value_matches(actual, v, event) for v in expected.values)
    if isinstance(expected, SigmaString):  # includes SigmaCasedString
        return _string_regex(expected).fullmatch(_to_str(actual)) is not None
    if isinstance(expected, SigmaRegularExpression):
        flags = 0
        for f in expected.flags:
            flags |= _REGEX_FLAGS[f]
        return re.search(expected.regexp.original, _to_str(actual), flags) is not None
    if isinstance(expected, SigmaBool):
        if isinstance(actual, bool):
            return actual == expected.boolean
        return _to_str(actual).lower() == str(expected.boolean).lower()
    if isinstance(expected, SigmaNumber):
        num = _to_number(actual)
        return num is not None and num == expected.number
    if isinstance(expected, SigmaCompareExpression):
        num = _to_number(actual)
        if num is None:
            return False
        target = expected.number.number
        op = expected.op
        ops = SigmaCompareExpression.CompareOperators
        return {
            ops.LT: num < target,
            ops.LTE: num <= target,
            ops.GT: num > target,
            ops.GTE: num >= target,
            ops.NEQ: num != target,
        }[op]
    if isinstance(expected, SigmaCIDRExpression):
        try:
            return ipaddress.ip_address(_to_str(actual)) in expected.network
        except ValueError:
            return False
    if isinstance(expected, SigmaFieldReference):
        other = _get_field(event, expected.field)
        return other is not _MISSING and _to_str(other).lower() == _to_str(actual).lower()
    raise UnsupportedSigmaFeature(f"value type {type(expected).__name__}")


def _string_regex(s: SigmaString) -> re.Pattern[str]:
    parts = []
    for part in s.s:
        if isinstance(part, str):
            parts.append(re.escape(part))
        elif part == SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:  # placeholders (%var%) need a SIEM-side expansion
            raise UnsupportedSigmaFeature(f"string part {part!r}")
    flags = re.DOTALL
    if not isinstance(s, SigmaCasedString):
        flags |= re.IGNORECASE
    return re.compile("".join(parts), flags)


def _to_str(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def _to_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
