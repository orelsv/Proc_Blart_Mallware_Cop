param(
    [string]$MockDir = ".\vt_test_files\mock_vt_responses",
    [string[]]$Process = @("notepad","explorer","cmd","powershell","python"),
    [ValidateSet("malicious","suspicious","undetected")]
    [string]$Status = "malicious"
)

# ensure mock dir
if (-not (Test-Path -Path $MockDir)) {
    New-Item -ItemType Directory -Path $MockDir | Out-Null
}

# map status -> stats
$statsMap = @{
    "malicious" = @{ malicious = 1; suspicious = 0; undetected = 0; harmless = 0 }
    "suspicious" = @{ malicious = 0; suspicious = 1; undetected = 0; harmless = 0 }
    "undetected" = @{ malicious = 0; suspicious = 0; undetected = 10; harmless = 0 }
}

$targets = @()
foreach ($p in $Process) {
    try {
        $targets += Get-Process -Name $p -ErrorAction Stop
    } catch {
        Write-Host "Process '$p' not found."
    }
}

foreach ($t in $targets | Sort-Object -Property Name -Unique) {
    try {
        $path = $t.MainModule.FileName
    } catch {
        Write-Host "No access to $($t.Name) (PID $($t.Id)). Try running PowerShell as Administrator."
        continue
    }
    if (-not (Test-Path -Path $path)) {
        Write-Host "File not found for $($t.Name): $path"
        continue
    }
    try {
        $hash = (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLower()
    } catch {
        Write-Host "Hash failed for $path"
        continue
    }

    $obj = @{
        sha256 = $hash
        name = [System.IO.Path]::GetFileName($path)
        last_analysis_stats = $statsMap[$Status]
        last_analysis_date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    } | ConvertTo-Json -Depth 4

    $outfile = Join-Path $MockDir ($hash + "_" + $Status + ".json")
    $obj | Out-File -FilePath $outfile -Encoding utf8
    Write-Host "Wrote mock: $outfile"
}

Write-Host "Done."