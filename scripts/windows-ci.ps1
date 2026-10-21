param([string]$Go = "go")
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Build under the runner account, then execute native tests under a temporary
# standard user when the hosted runner is elevated. Passwords never enter argv,
# files, environment variables or logs. No test bypass permits elevated probes.
$testBase = $env:RUNNER_TEMP
$root = ""
$username = "emslop" + [guid]::NewGuid().ToString("N").Substring(0, 10)
$createdUser = $false
$credential = $null
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($admin) { $testBase = [Environment]::GetFolderPath("CommonApplicationData") }
$root = Join-Path $testBase ("emudhraslop-tests-" + [guid]::NewGuid().ToString("N"))
$node = (Get-Command node.exe -ErrorAction Stop).Source
$python = (Get-Command python.exe -ErrorAction Stop).Source
$systemRoot = [Environment]::GetFolderPath("Windows")

try {
    New-Item -ItemType Directory -Path $root | Out-Null
    $packages = @(& $Go list -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' ./internal/... | Where-Object { $_ })
    if ($LASTEXITCODE -ne 0 -or $packages.Count -eq 0) { throw "Cannot enumerate native tests" }
    $testFiles = @()
    foreach ($package in $packages) {
        $name = ($package -replace '[^A-Za-z0-9]', '_') + '.test.exe'
        $path = Join-Path $root $name
        & $Go test -c -o $path $package
        if ($LASTEXITCODE -ne 0) { throw "Test compilation failed: $package" }
        $testFiles += $path
    }
    if ($admin) {
        $runTest = $testFiles | Where-Object { $_ -match '_run\.test\.exe$' }
        & $runTest '-test.run=^TestWindowsElevationRefused$' '-test.v'
        if ($LASTEXITCODE -ne 0) { throw "Elevated execution refusal failed" }
        $random = [byte[]]::new(48)
        [Security.Cryptography.RandomNumberGenerator]::Fill($random)
        $password = ConvertTo-SecureString ([Convert]::ToBase64String($random) + 'aA!9') -AsPlainText -Force
        [Array]::Clear($random, 0, $random.Length)
        $user = New-LocalUser -Name $username -Password $password -AccountNeverExpires -PasswordNeverExpires
        $createdUser = $true
        $usersGroup = Get-LocalGroup -SID 'S-1-5-32-545'
        Add-LocalGroupMember -Group $usersGroup.Name -Member $username
        $credential = [pscredential]::new("$env:COMPUTERNAME\$username", $password)
        $sid = $user.SID.Value
        & icacls.exe $root /inheritance:r /grant:r "*${sid}:(OI)(CI)M" '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Cannot grant isolated test directory access" }
    }

    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\install.ps1') -Destination (Join-Path $root 'install.ps1')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'test-install-windows.ps1') -Destination (Join-Path $root 'test-install-windows.ps1')
    $testRuns = @($testFiles | ForEach-Object { @{ Path = $_; Arguments = '-test.v -test.timeout=4m' } })
    $shells = @((Join-Path $systemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'), (Get-Command pwsh.exe -ErrorAction Stop).Source)
    foreach ($shell in $shells) {
        $testRuns += @{ Path = $shell; Arguments = '-NoLogo -NoProfile -NonInteractive -File "' + (Join-Path $root 'test-install-windows.ps1') + '" -Installer "' + (Join-Path $root 'install.ps1') + '" -Smoke' }
    }
    foreach ($run in $testRuns) {
        $path = $run.Path
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $path
        $start.Arguments = $run.Arguments
        $start.WorkingDirectory = $root
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.Environment.Clear()
        $start.Environment['SystemRoot'] = $systemRoot
        # Windows PowerShell uses PATHEXT even for an absolute .exe path.
        # Without it, it may shell-open the file asynchronously as a document.
        $start.Environment['PATHEXT'] = '.COM;.EXE;.BAT;.CMD'
        $start.Environment['PATH'] = ((Split-Path $node), (Split-Path $python), (Join-Path $systemRoot 'System32')) -join ';'
        $start.Environment['TEMP'] = $root
        $start.Environment['TMP'] = $root
        $start.Environment['LOCALAPPDATA'] = Join-Path $root 'localappdata'
        $start.Environment['EMUDHRASLOP_TEST_PYTHON'] = $python
        if ($admin) {
            $start.UserName = $username
            $start.Domain = $env:COMPUTERNAME
            $start.Password = $credential.Password
            $start.LoadUserProfile = $true
        }
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $start
        if (-not $process.Start()) { throw "Native test process did not start" }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(600000)) {
            $process.Kill($true)
            throw "Native test process exceeded deadline"
        }
        Write-Host $stdout.GetAwaiter().GetResult()
        Write-Host $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw "Native Windows tests failed: $(Split-Path $path -Leaf)" }
        $process.Dispose()
    }
} finally {
    if ($createdUser) {
        Remove-LocalUser -Name $username -ErrorAction Continue
    }
    if (Test-Path $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Continue }
    $credential = $null
}
