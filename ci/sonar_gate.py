"""Wait for a SonarQube analysis to finish and fail the build if the quality gate fails.

Reads .scannerwork/report-task.txt written by the scanner. Token comes from SONAR_TOKEN.
Exit 0 gate passed, 1 gate failed, 2 could not get an answer.
"""

import base64
import json
import os
import sys
import time
import urllib.request


def _get(url, token):
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{token}:".encode()).decode())
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.load(resp)


def read_task(path):
    out = {}
    with open(path) as fh:
        for line in fh:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                out[k] = v
    return out


def gate(task_file, token, timeout=300, poll=3):
    task = read_task(task_file)
    deadline = time.time() + timeout
    while True:
        ce = _get(task["ceTaskUrl"], token)["task"]
        if ce["status"] == "SUCCESS":
            break
        if ce["status"] in ("FAILED", "CANCELED"):
            print(f"analysis {ce['status'].lower()}", file=sys.stderr)
            return 2
        if time.time() > deadline:
            print("timed out waiting for the analysis", file=sys.stderr)
            return 2
        time.sleep(poll)
    status = _get(f"{task['serverUrl']}/api/qualitygates/project_status?analysisId={ce['analysisId']}", token)[
        "projectStatus"
    ]
    for c in status.get("conditions", []):
        print(f"{c['status']:<6} {c['metricKey']} actual={c.get('actualValue')} limit={c.get('errorThreshold')}")
    print(f"quality gate: {status['status']}")
    return 0 if status["status"] == "OK" else 1


if __name__ == "__main__":
    token = os.environ.get("SONAR_TOKEN")
    if not token:
        print("set SONAR_TOKEN", file=sys.stderr)
        sys.exit(2)
    sys.exit(gate(sys.argv[1] if len(sys.argv) > 1 else ".scannerwork/report-task.txt", token))
