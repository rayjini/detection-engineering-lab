"""Detection-as-code tests for every Sigma rule under rules/.

For each rule this checks that it:
  * parses and carries the metadata an analyst needs (ID, ATT&CK tags, level...)
  * has curated sample logs: at least one true positive and one false positive
  * fires on every true-positive sample and stays silent on every false positive
  * converts to Elastic queries with the lab's processing pipelines

Sample layout (directory name = rule file name without .yml):

    tests/samples/<rule_stem>/true_positive/*.json   -> rule MUST match
    tests/samples/<rule_stem>/false_positive/*.json  -> rule must NOT match

Each JSON file holds one event using Sigma/Sysmon field names. Keys starting
with "_" (e.g. "_comment") are documentation and are ignored when matching.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import pytest
from sigma.rule import SigmaLevel, SigmaStatus

from pipeline.convert import REPO_ROOT, convert_file, rule_files
from pipeline.sigma_eval import load_rule, matches

SAMPLES_DIR = REPO_ROOT / "tests" / "samples"
RULE_FILES = rule_files()

ATTACK_TECHNIQUE = re.compile(r"^t\d{4}(\.\d{3})?$")
ATTACK_TACTICS = {
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
}
ALLOWED_STATUS = {SigmaStatus.EXPERIMENTAL, SigmaStatus.TEST, SigmaStatus.STABLE}
ALLOWED_LEVELS = set(SigmaLevel)


def _rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def _samples(rule_path: Path, kind: str) -> list[Path]:
    return sorted((SAMPLES_DIR / rule_path.stem / kind).glob("*.json"))


def _sample_cases():
    for rule_path in RULE_FILES:
        for kind, expected in (("true_positive", True), ("false_positive", False)):
            for sample in _samples(rule_path, kind):
                yield pytest.param(rule_path, sample, expected,
                                   id=f"{rule_path.stem}/{kind}/{sample.name}")


rule_param = pytest.mark.parametrize("rule_path", RULE_FILES, ids=lambda p: p.stem)


# --------------------------------------------------------------------------- #
# Repository-level checks
# --------------------------------------------------------------------------- #
def test_rules_exist():
    assert RULE_FILES, "no Sigma rules found under rules/"


def test_rule_ids_are_unique():
    ids = Counter(str(load_rule(p).id) for p in RULE_FILES)
    dupes = [i for i, n in ids.items() if n > 1]
    assert not dupes, f"duplicate rule ids: {dupes}"


def test_no_orphan_sample_directories():
    """A sample folder whose rule was renamed/deleted would silently stop being tested."""
    rule_stems = {p.stem for p in RULE_FILES}
    orphans = [d.name for d in SAMPLES_DIR.iterdir() if d.is_dir() and d.name not in rule_stems]
    assert not orphans, f"sample directories with no matching rule: {orphans}"


# --------------------------------------------------------------------------- #
# Per-rule metadata checks
# --------------------------------------------------------------------------- #
@rule_param
def test_rule_metadata(rule_path: Path):
    rule = load_rule(rule_path)
    problems = []

    if rule.id is None:
        problems.append("missing id (UUID)")
    for field in ("title", "description", "author", "date"):
        if not getattr(rule, field):
            problems.append(f"missing {field}")
    if rule.status not in ALLOWED_STATUS:
        problems.append(f"status must be one of {sorted(s.name.lower() for s in ALLOWED_STATUS)}")
    if rule.level not in ALLOWED_LEVELS:
        problems.append("missing or invalid level")
    if not rule.falsepositives:
        problems.append("missing falsepositives (document known benign triggers)")

    attack_tags = [t.name for t in rule.tags if t.namespace == "attack"]
    techniques = [t for t in attack_tags if ATTACK_TECHNIQUE.match(t)]
    invalid = [t for t in attack_tags
               if not ATTACK_TECHNIQUE.match(t) and t not in ATTACK_TACTICS
               and not re.match(r"^[gs]\d{4}$", t)]  # groups / software ids
    if not techniques:
        problems.append("needs at least one ATT&CK technique tag, e.g. attack.t1059.001")
    if invalid:
        problems.append(f"invalid ATT&CK tags: {invalid}")

    assert not problems, f"{_rel(rule_path)}: " + "; ".join(problems)


@rule_param
def test_rule_has_samples(rule_path: Path):
    missing = [kind for kind in ("true_positive", "false_positive") if not _samples(rule_path, kind)]
    assert not missing, (
        f"{_rel(rule_path)} has no {' / '.join(missing)} samples; "
        f"add JSON events under tests/samples/{rule_path.stem}/"
    )


# --------------------------------------------------------------------------- #
# Behaviour: does the rule fire on the right events?
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("rule_path,sample_path,expected", list(_sample_cases()))
def test_sample(rule_path: Path, sample_path: Path, expected: bool):
    rule = load_rule(rule_path)
    event = json.loads(sample_path.read_text(encoding="utf-8"))
    assert isinstance(event, dict), f"{_rel(sample_path)} must contain a single JSON object"

    result = matches(rule, event)
    if expected:
        assert result, f"MISSED DETECTION: {rule.title!r} did not fire on {_rel(sample_path)}"
    else:
        assert not result, f"FALSE POSITIVE: {rule.title!r} fired on {_rel(sample_path)}"


# --------------------------------------------------------------------------- #
# Conversion: will the rule actually run in Elastic?
# --------------------------------------------------------------------------- #
@rule_param
@pytest.mark.parametrize("target,fmt", [("lucene", "default"), ("lucene", "siem_rule_ndjson"), ("eql", "default")])
def test_rule_converts_to_elastic(rule_path: Path, target: str, fmt: str):
    result = convert_file(rule_path, target=target, fmt=fmt)
    text = result if isinstance(result, str) else "\n".join(map(str, result))
    assert text.strip(), f"{_rel(rule_path)} produced an empty {target}/{fmt} conversion"
