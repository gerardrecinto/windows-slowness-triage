import http.server
import json
import threading

import pytest

from ci import psa_to_sonar, sonar_gate


def test_convert_maps_severity_and_paths(tmp_path):
    items = [
        {
            "RuleName": "PSAvoidUsingWriteHost",
            "Severity": 1,
            "Line": 7,
            "Message": "m1",
            "ScriptPath": str(tmp_path / "src" / "a.psm1"),
        },
        {
            "RuleName": "PSUseDeclaredVarsMoreThanAssignments",
            "Severity": "Error",
            "Line": 0,
            "Message": "m2",
            "ScriptPath": "bin/b.ps1",
        },
    ]
    out = psa_to_sonar.convert(items, root=str(tmp_path))["issues"]
    assert out[0]["severity"] == "MAJOR" and out[0]["type"] == "CODE_SMELL"
    assert out[0]["primaryLocation"]["filePath"] == "src/a.psm1"
    assert out[1]["severity"] == "CRITICAL" and out[1]["type"] == "BUG"
    assert out[1]["primaryLocation"]["textRange"]["startLine"] == 1


def test_convert_accepts_a_single_object_and_empty_input():
    one = {"RuleName": "R", "Severity": 0, "Line": 3, "Message": "m", "ScriptPath": "x.ps1"}
    assert len(psa_to_sonar.convert(one)["issues"]) == 1
    assert psa_to_sonar.convert([])["issues"] == []


class _Sonar(http.server.BaseHTTPRequestHandler):
    gate = "OK"
    task_status = ["IN_PROGRESS", "SUCCESS"]

    def do_GET(self):
        if self.path.startswith("/api/ce/task"):
            st = self.task_status.pop(0) if len(self.task_status) > 1 else self.task_status[0]
            body = {"task": {"status": st, "analysisId": "A1"}}
        else:
            body = {
                "projectStatus": {
                    "status": self.gate,
                    "conditions": [
                        {"status": self.gate, "metricKey": "new_coverage", "actualValue": "50", "errorThreshold": "80"}
                    ],
                }
            }
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture
def server(tmp_path):
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Sonar)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    f = tmp_path / "report-task.txt"
    f.write_text(f"serverUrl={base}\nceTaskUrl={base}/api/ce/task?id=1\n")
    yield f
    srv.shutdown()


def test_gate_passes_after_waiting(server, capsys):
    _Sonar.gate, _Sonar.task_status = "OK", ["IN_PROGRESS", "SUCCESS"]
    assert sonar_gate.gate(str(server), "tok", poll=0.01) == 0
    assert "quality gate: OK" in capsys.readouterr().out


def test_gate_fails_on_error(server):
    _Sonar.gate, _Sonar.task_status = "ERROR", ["SUCCESS"]
    assert sonar_gate.gate(str(server), "tok", poll=0.01) == 1


def test_gate_gives_up_on_failed_analysis_and_on_timeout(server):
    _Sonar.task_status = ["FAILED"]
    assert sonar_gate.gate(str(server), "tok", poll=0.01) == 2
    _Sonar.task_status = ["IN_PROGRESS"]
    assert sonar_gate.gate(str(server), "tok", timeout=0.05, poll=0.01) == 2
