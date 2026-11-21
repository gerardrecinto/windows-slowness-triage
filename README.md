# windows-slowness-triage

Tells you why a Windows host feels slow, in one screen. A PowerShell module samples CPU, memory, disk queue, TCP states and the noisiest processes, then turns the sample into findings such as a handle leak, TIME_WAIT pile-up or CLOSE_WAIT build-up. CI runs on Windows and Linux, lints with PSScriptAnalyzer, and gates on SonarQube. A GitLab CI file does the same checks.

[![CI](https://github.com/gerardrecinto/windows-slowness-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/gerardrecinto/windows-slowness-triage/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/gerardrecinto/windows-slowness-triage)](LICENSE)

**[Live page](https://gerardrecinto.github.io/windows-slowness-triage/)**

## Run it

PowerShell 7 or Windows PowerShell 5.1. No admin rights needed.

```powershell
git clone https://github.com/gerardrecinto/windows-slowness-triage
cd windows-slowness-triage
./bin/slowhost.ps1 -SampleFile samples/handle-leak.json   # no host access, safe anywhere
./bin/slowhost.ps1                                         # this machine, about 2 seconds
```

The sample run prints:

```
host win-app-07  cpu 46.5%  mem 5200/16384 MB free  disk queue 0.3
CRITICAL HandleLeakSuspect  orders-api (pid 4120) holds 63211 handles
WARNING  TimeWaitPileUp     6400 sockets in TIME_WAIT (ephemeral port exhaustion risk)
```

Exit code is 2 on a critical finding, 1 on a warning with `-FailOn Warning`, else 0, so a pipeline or a monitoring check can use it.

Run the tests: `Install-Module Pester -RequiredVersion 5.7.1 -Force; Invoke-Pester tests`

## Rules

| Code | Fires when |
|---|---|
| CpuHigh, CpuSaturated | CPU at or above 80%, 90% |
| MemoryLow, MemoryPressure | available memory under 20%, 10% |
| HandleLeakSuspect | a process holds 10,000 (warning) or 50,000 (critical) handles |
| ThreadCountHigh | a process has 2,000 or more threads |
| TimeWaitPileUp | 5,000 or more sockets in TIME_WAIT |
| CloseWaitPileUp | 500 or more sockets in CLOSE_WAIT |
| DiskQueue | queue length 2 (warning) or 5 (critical) |

Thresholds are parameters of `Test-HostSample`. They are rules of thumb, not universal limits; tune them to the host.

## CI

- **GitHub Actions** (`.github/workflows/ci.yml`): Pester and PSScriptAnalyzer on `windows-latest` and `ubuntu-latest`, Python tests, and a SonarQube Community container that is scanned and held to its quality gate.
- **GitLab CI** (`.gitlab-ci.yml`): the same checks. The Python job was run locally with gitlab-ci-local. The Windows job needs a runner tagged `windows` and has not run on one. The SonarQube job runs only when `SONAR_HOST_URL` and `SONAR_TOKEN` are set.
- **SonarQube and PowerShell:** SonarQube Community does not analyze PowerShell. `ci/psa_to_sonar.py` converts PSScriptAnalyzer results into Sonar's generic issue format so they sit under the same gate as the Python code. `ci/sonar_gate.py` waits for the analysis and fails the build when the gate fails.

## What is verified

- Pester passes on macOS (PowerShell 7.7) locally. The Windows-only collector test (`Get-NetTCPConnection`) runs on the `windows-latest` job.
- The sample files are synthetic. The live collector on Windows reads standard counters and CIM; on Linux and macOS it returns the same shape from `/proc` or an approximation, so the tests can run anywhere.
- No claim is made about a particular production host. The rules encode common causes of slowness (handle leaks, socket exhaustion, runaway threads), not a diagnosis.

MIT licensed.
