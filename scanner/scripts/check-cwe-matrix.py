#!/usr/bin/env python3
"""Check that every rule in rules.edn has a CWE and a :implemented row in
zap-cwe-matrix.edn with the same CWE. Runs in the coverage gate.
Stdlib only. Exit 1 on any mismatch.
"""
import re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "resources/zap_proxy/rules/rules.edn"
MATRIX = ROOT / "resources/zap_proxy/catalog/zap-cwe-matrix.edn"

def parse_rules(text):
    # each rule block contains :zap-proxy.rule/id "..." and :zap-proxy.rule/cwe "..."
    ids = re.findall(r':zap-proxy\.rule/id\s+"(\d+)"', text)
    cwes = re.findall(r':zap-proxy\.rule/cwe\s+"(CWE-\d+)"', text)
    if len(ids) != len(cwes):
        return None
    return dict(zip(ids, cwes))

def parse_matrix(text):
    impl = text.split(":open-gap")[0]
    ids = re.findall(r':rule-id\s+"(\d+)"', impl)
    cwes = re.findall(r':cwe\s+"(CWE-\d+)"', impl)
    if len(ids) != len(cwes):
        return None
    return dict(zip(ids, cwes))

def main():
    rules = parse_rules(RULES.read_text(encoding="utf-8"))
    matrix = parse_matrix(MATRIX.read_text(encoding="utf-8"))
    if rules is None or matrix is None:
        print("FAIL: could not parse rules/matrix id<->cwe pairing", file=sys.stderr)
        return 1
    missing = [r for r in rules if r not in matrix]
    extra = [r for r in matrix if r not in rules]
    cwe_mismatch = [r for r in rules if r in matrix and rules[r] != matrix[r]]
    no_cwe = [r for r, c in rules.items() if not c]
    if missing or extra or cwe_mismatch or no_cwe:
        print(f"FAIL: missing={missing} extra={extra} cwe_mismatch={cwe_mismatch} no_cwe={no_cwe}", file=sys.stderr)
        return 1
    print("CWE matrix OK: %d/%d rules implemented with CWE" % (len(rules), len(rules)))
    return 0

if __name__ == "__main__":
    sys.exit(main())
