<#
.SYNOPSIS
Print what is making this host slow. Exit 2 on a critical finding, 1 on a warning with -FailOn Warning, else 0.
.EXAMPLE
pwsh bin/slowhost.ps1                      # live host
pwsh bin/slowhost.ps1 -SampleFile samples/handle-leak.json
#>
[CmdletBinding()]
param([string]$SampleFile, [ValidateSet('Critical', 'Warning')][string]$FailOn = 'Critical', [int]$TopCount = 5)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../src/WinTriage/WinTriage.psm1') -Force
$out = @(Invoke-SlowHostReport -SampleFile $SampleFile -TopCount $TopCount)
$out | Where-Object { $_ -is [string] }
$result = $out | Where-Object { $_ -isnot [string] } | Select-Object -Last 1
$sev = @($result.Findings | ForEach-Object { $_.Severity })
if ($sev -contains 'Critical') { exit 2 }
if ($FailOn -eq 'Warning' -and $sev -contains 'Warning') { exit 1 }
exit 0
