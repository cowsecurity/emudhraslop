#requires -Version 5.1
param([switch]$Smoke, [string]$InstallVersion = '0.1.0', [string]$Installer = '')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $Installer) { $Installer = Join-Path (Split-Path $PSScriptRoot) 'install.ps1' }

# Load the exact shipped function definitions, without invoking its entrypoint.
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Installer has PowerShell parse errors.' }
foreach ($definition in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
Initialize-Installer
$arch = [EmudhraslopInstall.Native]::Architecture()
$root = Join-Path ([IO.Path]::GetTempPath()) ('emudhraslop-installer-test-' + [guid]::NewGuid().ToString('N'))
[EmudhraslopInstall.Native]::PrivateDirectory($root)

function Expect-Failure([string]$Name, [scriptblock]$Action) {
    $failed = $false
    try { & $Action | Out-Null } catch { $failed = $true }
    if (-not $failed) { throw "Expected rejection: $Name" }
    Write-Host "PASS: $Name rejected"
}
function New-TestZip([string[]]$Names, [int]$Attributes = 0, [switch]$WrongMachine) {
    $path = Join-Path $root ([guid]::NewGuid().ToString('N') + '.zip')
    $file = [IO.File]::Open($path, [IO.FileMode]::CreateNew)
    $zip = [IO.Compression.ZipArchive]::new($file, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $Names) {
            $entry = $zip.CreateEntry($name); $entry.ExternalAttributes = $Attributes
            $stream = $entry.Open()
            $data = New-Object byte[] 128
            $data[0] = 0x4D; $data[1] = 0x5A; $data[60] = 64
            $data[64] = 0x50; $data[65] = 0x45
            if (($arch -eq 'amd64') -xor $WrongMachine.IsPresent) { $data[68] = 0x64; $data[69] = 0x86 }
            else { $data[68] = 0x64; $data[69] = 0xAA }
            try { $stream.Write($data,0,$data.Length) } finally { $stream.Dispose() }
        }
    } finally { $zip.Dispose(); $file.Dispose() }
    return $path
}
function Hash-File([string]$Path) {
    $stream = [IO.File]::OpenRead($Path); $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
}

try {
    foreach ($value in @('../0.1.0', 'v0.1.0', '01.2.3', "0.1.0`n", '0.1.0;whoami')) {
        Expect-Failure 'invalid release version' { Assert-Version $value }
    }
    Assert-Version '0.1.0'; Assert-Version '1.2.3-rc.1+build.2'
    foreach ($value in @('http://github.com/test', 'https://github.com.evil.test/test', 'https://user:pass@github.com/test', 'file:///C:/test', 'https://github.com:444/test')) {
        Expect-Failure 'unsafe download URL' { Assert-DownloadUri ([uri]$value) }
    }
    foreach ($value in @('relative\bin', 'C:\', '\\invalid.example\share\bin', '\\?\C:\bin', 'C:\foo\..\bar', 'C:\foo\bar:ads', 'C:\NUL\bin', 'C:\foo.\bar')) {
        Expect-Failure 'unsafe destination' { [EmudhraslopInstall.Native]::LockDirectory($value) }
    }
    $lease = [EmudhraslopInstall.Native]::LockDirectory((Join-Path $root 'safe\bin'))
    try {
        [IO.File]::WriteAllText([IO.Path]::Combine($lease.Path,'probe.txt'),'test')
        Expect-Failure 'locked destination rename' { [IO.Directory]::Move((Join-Path $root 'safe'), (Join-Path $root 'moved')) }
    } finally { $lease.Dispose() }
    $shared = Join-Path $root 'shared'
    [IO.Directory]::CreateDirectory($shared) | Out-Null
    $acl = Get-Acl -LiteralPath $shared
    $everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($everyone, [Security.AccessControl.FileSystemRights]::Write, [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule); Set-Acl -LiteralPath $shared -AclObject $acl
    Expect-Failure 'destination writable by other users' { [EmudhraslopInstall.Native]::LockDirectory($shared) }
    $junction = Join-Path $root 'junction'
    New-Item -ItemType Junction -Path $junction -Target (Join-Path $root 'safe') | Out-Null
    try { Expect-Failure 'junction destination' { [EmudhraslopInstall.Native]::LockDirectory((Join-Path $junction 'bin')) } }
    finally { [IO.Directory]::Delete($junction) }

    $archive = New-TestZip @('README.md','emudhraslop.exe')
    $checksums = Join-Path $root 'SHA256SUMS'; $digest = Hash-File $archive
    [IO.File]::WriteAllText($checksums, "$digest  release.zip`n")
    Assert-ArchiveHash $checksums $archive 'release.zip'
    [IO.File]::WriteAllText($checksums, "$digest  release.zip`n$digest  release.zip`n")
    Expect-Failure 'duplicate checksum records' { Assert-ArchiveHash $checksums $archive 'release.zip' }
    [IO.File]::WriteAllText($checksums, "$digest  other.zip`n")
    Expect-Failure 'checksum for wrong archive' { Assert-ArchiveHash $checksums $archive 'release.zip' }
    [IO.File]::WriteAllText($checksums, ('0' * 64) + "  release.zip`n")
    Expect-Failure 'checksum mismatch' { Assert-ArchiveHash $checksums $archive 'release.zip' }
    $extracted = Join-Path $root 'extracted.exe'
    Expand-Executable $archive $extracted $arch
    if (-not [IO.File]::Exists($extracted) -or [IO.File]::Exists((Join-Path $root 'README.md'))) { throw 'Extraction was not executable-only.' }
    foreach ($names in @(@('emudhraslop.exe','../escape'), @('emudhraslop.exe','EMUDHRASLOP.EXE'), @('nested/emudhraslop.exe'), @('emudhraslop.exe','C:/escape'), @('emudhraslop.exe','folder\escape'))) {
        $bad = New-TestZip $names
        Expect-Failure 'unsafe or missing executable ZIP' { Expand-Executable $bad (Join-Path $root 'bad.exe') $arch }
    }
    $linked = New-TestZip @('emudhraslop.exe') -Attributes ([int](-1610612736)) # Unix symlink mode 0120000 << 16.
    Expect-Failure 'ZIP symlink' { Expand-Executable $linked (Join-Path $root 'linked.exe') $arch }
    $wrong = New-TestZip @('emudhraslop.exe') -WrongMachine
    Expect-Failure 'wrong native architecture' { Expand-Executable $wrong (Join-Path $root 'wrong.exe') $arch }
    Write-Host 'PASS: installer validation and extraction boundaries'

    if ($Smoke) {
        $destination = Join-Path $root 'installed'
        $oldPath = $env:PATH
        & $Installer -Version $InstallVersion -BinDir $destination
        $binary = Join-Path $destination 'emudhraslop.exe'
        $actual = & $binary version
        if ($LASTEXITCODE -ne 0 -or $actual.Trim() -ne $InstallVersion) { throw 'Downloaded executable failed real version smoke test.' }
        $digest = Hash-File $binary
        & $Installer -Version $InstallVersion -BinDir $destination
        if ((Hash-File $binary) -ne $digest -or $env:PATH -cne $oldPath) { throw 'Upgrade changed expected bytes or PATH.' }
        $locked = [IO.File]::Open($binary,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try { Expect-Failure 'upgrade of locked executable' { & $Installer -Version $InstallVersion -BinDir $destination } }
        finally { $locked.Dispose() }
        if ((Hash-File $binary) -ne $digest) { throw 'Failed upgrade damaged prior installation.' }
        if (@([IO.Directory]::GetDirectories($destination,'.install-*')).Count) { throw 'Installer left staging files behind.' }
        Write-Host "PASS: real release install, upgrade, failure preservation ($arch; PowerShell $($PSVersionTable.PSVersion))"
    }
} finally { [IO.Directory]::Delete($root,$true) }
