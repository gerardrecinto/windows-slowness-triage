BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/WinTriage/WinTriage.psm1') -Force
    function Load($name) { Get-Content -Raw (Join-Path $PSScriptRoot "../samples/$name.json") | ConvertFrom-Json }
    function Codes($f) { @($f | ForEach-Object { $_.Code }) }
}

Describe 'Test-HostSample' {
    It 'reports nothing for a healthy host' {
        (Test-HostSample -Sample (Load 'healthy')).Count | Should -Be 0
    }
    It 'finds a handle leak and TIME_WAIT pile-up, and nothing critical elsewhere' {
        $f = Test-HostSample -Sample (Load 'handle-leak')
        Codes $f | Should -Contain 'HandleLeakSuspect'
        Codes $f | Should -Contain 'TimeWaitPileUp'
        ($f | Where-Object Code -eq 'HandleLeakSuspect').Severity | Should -Be 'Critical'
        Codes $f | Should -Not -Contain 'CpuSaturated'
    }
    It 'finds CPU, memory, disk, thread and CLOSE_WAIT problems on a starved host' {
        $codes = Codes (Test-HostSample -Sample (Load 'cpu-starved'))
        $codes | Should -Contain 'CpuSaturated'
        $codes | Should -Contain 'MemoryPressure'
        $codes | Should -Contain 'DiskQueue'
        $codes | Should -Contain 'ThreadCountHigh'
        $codes | Should -Contain 'CloseWaitPileUp'
    }
    It 'treats the threshold as inclusive and honours overrides' {
        $s = Load 'healthy'
        $s.cpuPercent = 80
        Codes (Test-HostSample -Sample $s) | Should -Contain 'CpuHigh'
        Codes (Test-HostSample -Sample $s -CpuWarn 85) | Should -Not -Contain 'CpuHigh'
    }
    It 'handles a live-style hashtable of TCP states' {
        $s = Load 'healthy'
        $s.tcp = @{ TimeWait = 9000 }
        Codes (Test-HostSample -Sample $s) | Should -Contain 'TimeWaitPileUp'
    }
}

Describe 'Get-HostSample' {
    It 'returns the expected shape on this machine' {
        $s = Get-HostSample -TopCount 3
        $s.cpuPercent | Should -BeGreaterOrEqual 0
        $s.memory.totalMB | Should -BeGreaterThan 0
        @($s.processes).Count | Should -BeGreaterThan 0
        $s.PSObject.Properties.Name | Should -Contain 'tcp'
    }
    It 'collects TCP state counts from Get-NetTCPConnection' -Skip:(-not ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows)) {
        (Get-HostSample).tcp.Keys.Count | Should -BeGreaterThan 0
    }
}

Describe 'slowhost.ps1 exit codes' {
    It 'exits 0 when healthy' {
        pwsh -NoProfile -File (Join-Path $PSScriptRoot '../bin/slowhost.ps1') -SampleFile (Join-Path $PSScriptRoot '../samples/healthy.json') | Out-Null
        $LASTEXITCODE | Should -Be 0
    }
    It 'exits 2 on a critical finding' {
        pwsh -NoProfile -File (Join-Path $PSScriptRoot '../bin/slowhost.ps1') -SampleFile (Join-Path $PSScriptRoot '../samples/handle-leak.json') | Out-Null
        $LASTEXITCODE | Should -Be 2
    }
}
