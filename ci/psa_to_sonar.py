"""Turn PSScriptAnalyzer JSON into SonarQube's generic issue format.

SonarQube Community does not analyze PowerShell. Importing PSScriptAnalyzer results as external
issues puts them next to the Python findings and under the same quality gate.

    pwsh -c "Invoke-ScriptAnalyzer -Path src,bin -Recurse | ConvertTo-Json -Depth 3" > psa.json
    python ci/psa_to_sonar.py psa.json > psa-sonar.json
"""

import json
import os
import sys

SEVERITY = {"error": "CRITICAL", "parseerror": "BLOCKER", "warning": "MAJOR", "information": "INFO"}
# PSScriptAnalyzer serializes Severity as a number when asked for JSON: 0 Information, 1 Warning, 2 Error, 3 ParseError.
NUMERIC = {0: "information", 1: "warning", 2: "error", 3: "parseerror"}


def convert(items, root="."):
    if isinstance(items, dict):
        items = [items]
    issues = []
    for it in items or []:
        sev = it.get("Severity", "warning")
        sev = NUMERIC.get(sev, str(sev).lower())
        path = os.path.relpath(it["ScriptPath"], root) if os.path.isabs(it["ScriptPath"]) else it["ScriptPath"]
        issues.append(
            {
                "engineId": "PSScriptAnalyzer",
                "ruleId": it["RuleName"],
                "severity": SEVERITY.get(sev, "MAJOR"),
                "type": "BUG" if sev in ("error", "parseerror") else "CODE_SMELL",
                "primaryLocation": {
                    "message": it["Message"],
                    "filePath": path.replace("\\", "/"),
                    "textRange": {"startLine": max(1, int(it.get("Line") or 1))},
                },
            }
        )
    return {"issues": issues}


def main(argv):
    if len(argv) != 2:
        print("usage: psa_to_sonar.py psa.json", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8-sig") as fh:
        text = fh.read().strip()
    json.dump(convert(json.loads(text) if text else []), sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
