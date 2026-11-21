Set-StrictMode -Version Latest

function Test-IsWindows {
    if ($PSVersionTable.PSEdition -eq 'Desktop') { return $true }
    $v = Get-Variable -Name IsWindows -ErrorAction SilentlyContinue
    return [bool]($v -and $v.Value)
}

function Get-HostSample {
    <#
    .SYNOPSIS
    One snapshot of what makes a host feel slow: CPU, memory, disk queue, TCP states, noisy processes.
    Windows is the target. On Linux it returns the same shape from /proc so the tests can run anywhere.
    #>
    [CmdletBinding()]
    param([int]$TopCount = 5)

    if (Test-IsWindows) {
        $cpu = (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 1).CounterSamples[0].CookedValue
        $os = Get-CimInstance Win32_OperatingSystem
        $totalMB = [math]::Round($os.TotalVisibleMemorySize / 1024)
        $availMB = [math]::Round($os.FreePhysicalMemory / 1024)
        $queue = (Get-Counter '\PhysicalDisk(_Total)\Current Disk Queue Length').CounterSamples[0].CookedValue
        $tcp = @{}
        Get-NetTCPConnection -ErrorAction SilentlyContinue | Group-Object State | ForEach-Object { $tcp[[string]$_.Name] = $_.Count }
    }
    else {
        $cpu = 0
        if (Test-Path /proc/stat) {
            $a = (Get-Content /proc/stat -TotalCount 1) -split '\s+' | Select-Object -Skip 1 | ForEach-Object { [double]$_ }
            Start-Sleep -Seconds 1
            $b = (Get-Content /proc/stat -TotalCount 1) -split '\s+' | Select-Object -Skip 1 | ForEach-Object { [double]$_ }
            $total = ($b | Measure-Object -Sum).Sum - ($a | Measure-Object -Sum).Sum
            $idle = ($b[3] + $b[4]) - ($a[3] + $a[4])
            if ($total -gt 0) { $cpu = 100.0 * ($total - $idle) / $total }
        }
        if (Test-Path /proc/meminfo) {
            $mem = @{}
            Get-Content /proc/meminfo | ForEach-Object { if ($_ -match '^(\w+):\s+(\d+)') { $mem[$Matches[1]] = [double]$Matches[2] } }
            $totalMB = [math]::Round($mem['MemTotal'] / 1024)
            $availMB = [math]::Round($mem['MemAvailable'] / 1024)
        }
        else {
            # macOS and other hosts: approximate from the process list.
            $totalMB = [math]::Round([GC]::GetGCMemoryInfo().TotalAvailableMemoryBytes / 1MB)
            $used = (Get-Process | Measure-Object WorkingSet64 -Sum).Sum / 1MB
            $availMB = [math]::Max(0, $totalMB - [math]::Round($used))
        }
        $queue = 0
        $tcp = @{}
    }

    $procs = Get-Process | ForEach-Object {
        [pscustomobject]@{
            name = $_.ProcessName
            id = $_.Id
            cpuSeconds = [math]::Round([double]($_.CPU), 1)
            handles = [int]$_.HandleCount
            threads = [int]$_.Threads.Count
            workingSetMB = [math]::Round($_.WorkingSet64 / 1MB)
        }
    }
    $top = @($procs | Sort-Object cpuSeconds -Descending | Select-Object -First $TopCount) +
    @($procs | Sort-Object handles -Descending | Select-Object -First $TopCount) +
    @($procs | Sort-Object threads -Descending | Select-Object -First $TopCount)

    [pscustomobject]@{
        host = [System.Net.Dns]::GetHostName()
        collected = (Get-Date).ToUniversalTime().ToString('o')
        cpuPercent = [math]::Round($cpu, 1)
        memory = [pscustomobject]@{ totalMB = $totalMB; availableMB = $availMB }
        diskQueue = [math]::Round([double]$queue, 2)
        tcp = $tcp
        processes = @($top | Sort-Object id -Unique)
    }
}

function Test-HostSample {
    <#
    .SYNOPSIS
    Turn a sample into findings. Pure function: no host access, so it is the part the tests cover most.
    #>
    [CmdletBinding()]
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory)] $Sample,
        [double]$CpuWarn = 80, [double]$CpuCrit = 90,
        [double]$MemAvailWarnPct = 20, [double]$MemAvailCritPct = 10,
        [int]$HandlesWarn = 10000, [int]$HandlesCrit = 50000,
        [int]$ThreadsWarn = 2000,
        [int]$TimeWaitWarn = 5000, [int]$CloseWaitWarn = 500,
        [double]$DiskQueueWarn = 2, [double]$DiskQueueCrit = 5
    )
    $findings = [System.Collections.Generic.List[object]]::new()
    function Add-Finding($Sev, $Code, $Msg) {
        $findings.Add([pscustomobject]@{ Severity = $Sev; Code = $Code; Message = $Msg })
    }

    if ($Sample.cpuPercent -ge $CpuCrit) { Add-Finding -Sev Critical -Code CpuSaturated -Msg "CPU at $($Sample.cpuPercent)%" }
    elseif ($Sample.cpuPercent -ge $CpuWarn) { Add-Finding -Sev Warning -Code CpuHigh -Msg "CPU at $($Sample.cpuPercent)%" }

    if ($Sample.memory.totalMB -gt 0) {
        $pct = [math]::Round(100.0 * $Sample.memory.availableMB / $Sample.memory.totalMB, 1)
        if ($pct -lt $MemAvailCritPct) { Add-Finding -Sev Critical -Code MemoryPressure -Msg "$pct% memory available" }
        elseif ($pct -lt $MemAvailWarnPct) { Add-Finding -Sev Warning -Code MemoryLow -Msg "$pct% memory available" }
    }

    foreach ($p in $Sample.processes) {
        if ($p.handles -ge $HandlesCrit) { Add-Finding -Sev Critical -Code HandleLeakSuspect -Msg "$($p.name) (pid $($p.id)) holds $($p.handles) handles" }
        elseif ($p.handles -ge $HandlesWarn) { Add-Finding -Sev Warning -Code HandleLeakSuspect -Msg "$($p.name) (pid $($p.id)) holds $($p.handles) handles" }
        if ($p.threads -ge $ThreadsWarn) { Add-Finding -Sev Warning -Code ThreadCountHigh -Msg "$($p.name) (pid $($p.id)) has $($p.threads) threads" }
    }

    $tw = if ($Sample.tcp.PSObject.Properties['TimeWait']) { [int]$Sample.tcp.TimeWait } elseif ($Sample.tcp -is [hashtable] -and $Sample.tcp.ContainsKey('TimeWait')) { [int]$Sample.tcp['TimeWait'] } else { 0 }
    $cw = if ($Sample.tcp.PSObject.Properties['CloseWait']) { [int]$Sample.tcp.CloseWait } elseif ($Sample.tcp -is [hashtable] -and $Sample.tcp.ContainsKey('CloseWait')) { [int]$Sample.tcp['CloseWait'] } else { 0 }
    if ($tw -ge $TimeWaitWarn) { Add-Finding -Sev Warning -Code TimeWaitPileUp -Msg "$tw sockets in TIME_WAIT (ephemeral port exhaustion risk)" }
    if ($cw -ge $CloseWaitWarn) { Add-Finding -Sev Warning -Code CloseWaitPileUp -Msg "$cw sockets in CLOSE_WAIT (an app is not closing connections)" }

    if ($Sample.diskQueue -ge $DiskQueueCrit) { Add-Finding -Sev Critical -Code DiskQueue -Msg "disk queue length $($Sample.diskQueue)" }
    elseif ($Sample.diskQueue -ge $DiskQueueWarn) { Add-Finding -Sev Warning -Code DiskQueue -Msg "disk queue length $($Sample.diskQueue)" }

    , @($findings)
}

function Invoke-SlowHostReport {
    <#
    .SYNOPSIS
    Print a one-screen report for a live host or a saved sample, and return the sample and findings.
    #>
    [CmdletBinding()]
    param([string]$SampleFile, [int]$TopCount = 5)
    $sample = if ($SampleFile) { Get-Content -Raw -LiteralPath $SampleFile | ConvertFrom-Json } else { Get-HostSample -TopCount $TopCount }
    $findings = Test-HostSample -Sample $sample
    Write-Output ("host {0}  cpu {1}%  mem {2}/{3} MB free  disk queue {4}" -f $sample.host, $sample.cpuPercent, $sample.memory.availableMB, $sample.memory.totalMB, $sample.diskQueue)
    if ($findings.Count -eq 0) { Write-Output 'no findings' }
    foreach ($f in $findings) { Write-Output ("{0,-8} {1,-18} {2}" -f $f.Severity.ToUpper(), $f.Code, $f.Message) }
    [pscustomobject]@{ Sample = $sample; Findings = $findings }
}

Export-ModuleMember -Function Get-HostSample, Test-HostSample, Invoke-SlowHostReport
