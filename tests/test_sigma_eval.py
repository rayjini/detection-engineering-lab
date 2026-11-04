"""Unit tests for the offline evaluator itself.

If the evaluator had a bug (e.g. always returning True), every true-positive
sample test would pass for the wrong reason. These tests pin down its Sigma
semantics on small inline rules.
"""

from __future__ import annotations

import pytest
from sigma.rule import SigmaRule

from pipeline.sigma_eval import UnsupportedSigmaFeature, matches


def rule(detection: str) -> SigmaRule:
    indented = "\n".join("  " + line for line in detection.strip().splitlines())
    return SigmaRule.from_yaml(
        "title: unit\n"
        "logsource: {category: process_creation, product: windows}\n"
        f"detection:\n{indented}\n"
    )


def test_endswith_is_case_insensitive():
    r = rule(r"""
sel:
  Image|endswith: '\powershell.exe'
condition: sel
""")
    assert matches(r, {"Image": r"C:\WINDOWS\System32\POWERSHELL.EXE"})
    assert not matches(r, {"Image": r"C:\Windows\System32\powershell.exe.bak"})


def test_plain_value_is_exact_match_not_substring():
    r = rule("""
sel:
  User: 'admin'
condition: sel
""")
    assert matches(r, {"User": "ADMIN"})
    assert not matches(r, {"User": "administrator"})


def test_list_values_are_ored_and_all_modifier_ands():
    any_rule = rule("""
sel:
  CommandLine|contains: ['foo', 'bar']
condition: sel
""")
    all_rule = rule("""
sel:
  CommandLine|contains|all: ['foo', 'bar']
condition: sel
""")
    assert matches(any_rule, {"CommandLine": "x bar y"})
    assert not matches(all_rule, {"CommandLine": "x bar y"})
    assert matches(all_rule, {"CommandLine": "bar then foo"})


def test_fields_in_one_selection_are_anded():
    r = rule("""
sel:
  Image|endswith: 'a.exe'
  CommandLine|contains: 'go'
condition: sel
""")
    assert matches(r, {"Image": "a.exe", "CommandLine": "go now"})
    assert not matches(r, {"Image": "a.exe", "CommandLine": "stop"})


def test_list_of_maps_is_ored():
    r = rule("""
sel:
  - Image|endswith: 'a.exe'
  - OriginalFileName: 'a.dll'
condition: sel
""")
    assert matches(r, {"Image": "x.exe", "OriginalFileName": "a.dll"})
    assert not matches(r, {"Image": "x.exe", "OriginalFileName": "x.dll"})


def test_not_and_one_of_selectors():
    r = rule("""
sel_a:
  F: 'a'
sel_b:
  F: 'b'
filter:
  G: 'skip'
condition: 1 of sel_* and not filter
""")
    assert matches(r, {"F": "b", "G": "keep"})
    assert not matches(r, {"F": "b", "G": "skip"})
    assert not matches(r, {"F": "c"})


def test_missing_field_does_not_match():
    r = rule("""
sel:
  CommandLine|contains: 'x'
condition: sel
""")
    assert not matches(r, {"Image": "x"})


def test_null_matches_missing_or_empty():
    r = rule("""
sel:
  ParentImage: null
condition: sel
""")
    assert matches(r, {"Image": "a"})
    assert matches(r, {"ParentImage": ""})
    assert not matches(r, {"ParentImage": "b"})


def test_cased_modifier():
    r = rule("""
sel:
  F|cased: 'Abc'
condition: sel
""")
    assert matches(r, {"F": "Abc"})
    assert not matches(r, {"F": "abc"})


def test_regex_modifier():
    r = rule("""
sel:
  CommandLine|re: '-[Ee]nc\\s+[A-Za-z0-9+/=]{20,}'
condition: sel
""")
    assert matches(r, {"CommandLine": "powershell -enc " + "A" * 24})
    assert not matches(r, {"CommandLine": "powershell -enc short"})


def test_windash_matches_slash_variant():
    r = rule("""
sel:
  CommandLine|windash|contains: ' -enc '
condition: sel
""")
    assert matches(r, {"CommandLine": "powershell /enc AAAA"})
    assert matches(r, {"CommandLine": "powershell -enc AAAA"})


def test_numbers_and_cidr():
    r = rule("""
sel:
  EventID: 3
  DestinationIp|cidr: '10.0.0.0/8'
condition: sel
""")
    assert matches(r, {"EventID": "3", "DestinationIp": "10.1.2.3"})
    assert not matches(r, {"EventID": 3, "DestinationIp": "192.168.1.1"})
    assert not matches(r, {"EventID": 3, "DestinationIp": "not-an-ip"})


def test_keyword_search_ignores_metadata_keys():
    r = rule("""
keywords:
  - 'mimikatz'
condition: keywords
""")
    assert matches(r, {"CommandLine": "run Mimikatz.exe"})
    assert not matches(r, {"_comment": "mimikatz", "CommandLine": "calc.exe"})


def test_placeholder_is_reported_as_unsupported():
    r = rule("""
sel:
  User|expand: '%admins%'
condition: sel
""")
    with pytest.raises(UnsupportedSigmaFeature):
        matches(r, {"User": "x"})
