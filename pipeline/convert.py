"""Convert Sigma rules to Elastic queries with pySigma.

Usage:
    python -m pipeline.convert                      # Lucene queries -> output/lucene/
    python -m pipeline.convert --format siem_rule_ndjson
        # -> output/lucene/rules.ndjson, importable via
        #    Kibana > Security > Rules > Import rules
    python -m pipeline.convert --target eql

Processing pipelines:
    sysmon       adds EventID / channel conditions for Sysmon log sources
    ecs_windows  maps Sigma field names to Winlogbeat >= 7 ECS fields
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sigma.backends.elasticsearch import EqlBackend, LuceneBackend
from sigma.collection import SigmaCollection
from sigma.plugins import InstalledSigmaPlugins

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
DEFAULT_PIPELINES = ["sysmon", "ecs_windows"]
BACKENDS = {"lucene": LuceneBackend, "eql": EqlBackend}


def rule_files(rules_dir: Path = RULES_DIR) -> list[Path]:
    return sorted(p for p in rules_dir.rglob("*.yml") if p.is_file())


def make_backend(target: str = "lucene", pipelines: list[str] | None = None):
    resolver = InstalledSigmaPlugins.autodiscover().get_pipeline_resolver()
    pipeline = resolver.resolve(pipelines or DEFAULT_PIPELINES)
    return BACKENDS[target](processing_pipeline=pipeline)


def convert_file(path: Path, target: str = "lucene", fmt: str = "default",
                 pipelines: list[str] | None = None):
    collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    return make_backend(target, pipelines).convert(collection, fmt)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", choices=sorted(BACKENDS), default="lucene")
    ap.add_argument("--format", default="default",
                    help="backend output format, e.g. default, siem_rule_ndjson, kibana_ndjson")
    ap.add_argument("--pipeline", action="append", dest="pipelines",
                    help=f"processing pipeline (repeatable, default: {' '.join(DEFAULT_PIPELINES)})")
    ap.add_argument("--rules", type=Path, default=RULES_DIR)
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "output")
    args = ap.parse_args(argv)

    out_dir = args.out / args.target
    out_dir.mkdir(parents=True, exist_ok=True)
    ndjson = args.format.endswith("ndjson")
    bundle: list[str] = []
    failures = 0

    for path in rule_files(args.rules):
        try:
            result = convert_file(path, args.target, args.format, args.pipelines)
        except Exception as exc:  # report every broken rule, then fail
            failures += 1
            print(f"FAIL {path.relative_to(REPO_ROOT)}: {exc}", file=sys.stderr)
            continue
        if ndjson:
            bundle.append(result if isinstance(result, str) else "\n".join(map(str, result)))
        else:
            text = "\n".join(map(str, result)) if isinstance(result, list) else str(result)
            (out_dir / f"{path.stem}.txt").write_text(text + "\n", encoding="utf-8")
            print(f"OK   {path.relative_to(REPO_ROOT)}\n     {text}")

    if ndjson:
        target_file = out_dir / "rules.ndjson"
        target_file.write_text("\n".join(bundle) + "\n", encoding="utf-8")
        print(f"wrote {len(bundle)} rule(s) to {target_file.relative_to(REPO_ROOT)}")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
