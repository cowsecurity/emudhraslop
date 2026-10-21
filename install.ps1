#requires -Version 5.1
[CmdletBinding()]
param([string]$Version = '', [string]$BinDir = '')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Initialize-Installer {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Run this installer on Windows.' }
    Add-Type -AssemblyName System.Net.Http
    Add-Type -AssemblyName System.IO.Compression
    if ('EmudhraslopInstall.Native' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
namespace EmudhraslopInstall {
 public sealed class Lease : IDisposable {
  public string Path;
  public List<SafeFileHandle> Handles = new List<SafeFileHandle>();
  public void Dispose() { foreach (var h in Handles) h.Dispose(); Handles.Clear(); }
 }
 public static class Native {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern uint QueryDosDevice(string name, StringBuilder buffer, int size);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool GetVolumeNameForVolumeMountPoint(string root, StringBuilder name, int size);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sa, uint creation, uint flags, IntPtr template);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
  [StructLayout(LayoutKind.Sequential)] struct Info {
   public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
   public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
  }
  [DllImport("kernel32.dll")] static extern void GetNativeSystemInfo(IntPtr info);
  [StructLayout(LayoutKind.Sequential)] struct SA { public int Length; public IntPtr Descriptor; public int Inherit; }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool CreateDirectory(string path, ref SA sa);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
  static extern uint GetNamedSecurityInfo(string name, int type, uint info, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
  [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
  public static void AssertPrivateDestination(string path) {
   IntPtr owner,group,dacl,sacl,descriptor;
   if (GetNamedSecurityInfo(path,1,5,out owner,out group,out dacl,out sacl,out descriptor) != 0) throw new IOException("Cannot read destination permissions.");
   try {
    byte[] bytes = new byte[GetSecurityDescriptorLength(descriptor)]; Marshal.Copy(descriptor,bytes,0,bytes.Length);
    var sd = new RawSecurityDescriptor(bytes,0); string sid = WindowsIdentity.GetCurrent().User.Value;
    if (sd.Owner == null || sd.Owner.Value != sid || sd.DiscretionaryAcl == null) throw new IOException("Choose a directory owned by your Windows account.");
    foreach (GenericAce entry in sd.DiscretionaryAcl) {
     var ace = entry as CommonAce;
     if (ace == null) throw new IOException("Unsupported destination permissions.");
     if (ace.AceQualifier != AceQualifier.AccessAllowed || (ace.AccessMask & 0x500D0156) == 0) continue;
     string who = ace.SecurityIdentifier.Value;
     if (who != sid && who != "S-1-5-18" && who != "S-1-5-32-544") throw new IOException("Destination is writable by another account. Choose a private directory.");
    }
   } finally { LocalFree(descriptor); }
  }
  public static string Architecture() {
   var p = Marshal.AllocHGlobal(64);
   try { GetNativeSystemInfo(p); int a = Marshal.ReadInt16(p); if (a == 9) return "amd64"; if (a == 12) return "arm64"; throw new IOException("Unsupported Windows architecture."); }
   finally { Marshal.FreeHGlobal(p); }
  }
  public static string LocalPath(string path) {
   if (String.IsNullOrEmpty(path) || path.Length > 160 || !System.Text.RegularExpressions.Regex.IsMatch(path, @"\A[A-Za-z]:\\")) throw new IOException("Use an absolute local drive path (maximum 160 characters).");
   string tail = path.Substring(3).TrimEnd('\\');
   if (tail.Length == 0) throw new IOException("Choose a directory below the drive root.");
   foreach (string part in tail.Split('\\')) {
    if (part.Length == 0 || part.EndsWith(".") || part.EndsWith(" ") || part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
        System.Text.RegularExpressions.Regex.IsMatch(part, @"\A(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)", System.Text.RegularExpressions.RegexOptions.IgnoreCase)) throw new IOException("Unsupported destination path.");
   }
   var b = new StringBuilder(1024);
   if (QueryDosDevice(path.Substring(0,2), b, b.Capacity) == 0 || !System.Text.RegularExpressions.Regex.IsMatch(b.ToString(), @"\A\\Device\\HarddiskVolume[0-9]+\z")) throw new IOException("Network, substituted and virtual drives are unsupported.");
   var volume = new StringBuilder(64);
   if (!GetVolumeNameForVolumeMountPoint(path.Substring(0,3),volume,volume.Capacity)) throw new IOException("Cannot resolve local volume.");
   return volume.ToString() + tail;
  }
  // Lock each ancestor against deletion/replacement before opening its child.
  // Access the resolved volume directly so a DOS drive remap cannot redirect writes.
  public static Lease LockDirectory(string path) {
   string physical = LocalPath(path); var lease = new Lease();
   int rootEnd = physical.IndexOf('}') + 2;
   string[] parts = physical.Substring(rootEnd).Split('\\');
   string current = physical.Substring(0,rootEnd);
   try {
    for (int i=0; i<=parts.Length; i++) {
     if (i > 0) current = Path.Combine(current,parts[i-1]);
     var h = CreateFile(current, 0x80, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
     if (h.IsInvalid && (Marshal.GetLastWin32Error() == 2 || Marshal.GetLastWin32Error() == 3) && i > 0) {
      h.Dispose(); Directory.CreateDirectory(current);
      h = CreateFile(current, 0x80, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
     }
     Info info;
     if (h.IsInvalid || !GetFileInformationByHandle(h, out info)) { h.Dispose(); throw new IOException("Cannot open destination directory."); }
     if ((info.Attributes & 0x400) != 0 || (info.Attributes & 0x10) == 0) { h.Dispose(); throw new IOException("Destination contains a reparse point or non-directory."); }
     lease.Handles.Add(h);
    }
    AssertPrivateDestination(physical);
    lease.Path = physical; return lease;
   } catch { lease.Dispose(); throw; }
  }
  public static void PrivateDirectory(string path) {
   string sid = WindowsIdentity.GetCurrent().User.Value;
   var sd = new RawSecurityDescriptor("O:"+sid+"D:P(A;OICI;FA;;;"+sid+")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
   byte[] bytes = new byte[sd.BinaryLength]; sd.GetBinaryForm(bytes,0);
   var pin = GCHandle.Alloc(bytes, GCHandleType.Pinned);
   try { var sa = new SA { Length=Marshal.SizeOf(typeof(SA)), Descriptor=pin.AddrOfPinnedObject() };
    if (!CreateDirectory(path,ref sa)) throw new IOException("Cannot create private staging directory.");
   } finally { pin.Free(); }
  }
 }
}
'@
}

function Assert-Version([string]$Value) {
    $number = '(0|[1-9][0-9]*)'
    $pre = '(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
    if ($Value.Length -gt 128 -or $Value -cnotmatch "\A$number\.$number\.$number(?:-$pre(?:\.$pre)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\z") {
        throw 'Version must be SemVer without a leading v, for example 0.1.0.'
    }
}

function Assert-DownloadUri([uri]$Uri) {
    if ($Uri.Scheme -ne 'https' -or $Uri.Port -ne 443 -or $Uri.UserInfo -or
        $Uri.Host -notin @('github.com', 'api.github.com', 'release-assets.githubusercontent.com')) {
        throw 'Download redirected outside the allowed GitHub HTTPS hosts.'
    }
}

function Receive-ReleaseFile([uri]$Uri, [string]$Path, [long]$Limit) {
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseDefaultCredentials = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('emudhraslop-installer')
    $deadline = [Threading.CancellationTokenSource]::new(120000)
    $response = $null; $stream = $null; $output = $null
    try {
        for ($redirect = 0; $redirect -le 5; $redirect++) {
            Assert-DownloadUri $Uri
            $response = $client.GetAsync($Uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $deadline.Token).GetAwaiter().GetResult()
            if ([int]$response.StatusCode -in @(301,302,303,307,308)) {
                if ($redirect -eq 5 -or -not $response.Headers.Location) { throw 'Too many or invalid redirects.' }
                $Uri = [uri]::new($Uri, $response.Headers.Location)
                $response.Dispose(); $response = $null
                continue
            }
            if (-not $response.IsSuccessStatusCode) { throw 'GitHub release download failed.' }
            if ($response.Content.Headers.ContentLength -gt $Limit) { throw 'Download exceeds size limit.' }
            $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $output = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $buffer = New-Object byte[] 65536
            [long]$total = 0
            while (($read = $stream.ReadAsync($buffer, 0, $buffer.Length, $deadline.Token).GetAwaiter().GetResult()) -gt 0) {
                $total += $read
                if ($total -gt $Limit) { throw 'Download exceeds size limit.' }
                $output.Write($buffer, 0, $read)
            }
            return
        }
    } finally {
        if ($output) { $output.Dispose() }; if ($stream) { $stream.Dispose() }
        if ($response) { $response.Dispose() }; $deadline.Dispose(); $client.Dispose(); $handler.Dispose()
    }
}

function Assert-ArchiveHash([string]$Checksums, [string]$Archive, [string]$Name) {
    $matchesForFile = @()
    foreach ($line in [IO.File]::ReadAllLines($Checksums)) {
        if ($line -cnotmatch '\A([0-9a-fA-F]{64}) [ *](.+)\z') { throw 'Malformed SHA256SUMS entry.' }
        if ($Matches[2] -ceq $Name) { $matchesForFile += $Matches[1] }
    }
    if ($matchesForFile.Count -ne 1) { throw 'SHA256SUMS must contain exactly one matching archive.' }
    $stream = [IO.File]::OpenRead($Archive); $hash = [Security.Cryptography.SHA256]::Create()
    try { $actual = [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $hash.Dispose() }
    if ($actual -cne $matchesForFile[0].ToLowerInvariant()) { throw 'Release checksum mismatch.' }
}

function Expand-Executable([string]$Archive, [string]$Destination, [string]$Arch) {
    $inputFile = [IO.File]::OpenRead($Archive)
    $zip = [IO.Compression.ZipArchive]::new($inputFile, [IO.Compression.ZipArchiveMode]::Read)
    try {
        if ($zip.Entries.Count -gt 128) { throw 'Too many archive entries.' }
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $binary = $null; [long]$total = 0
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            if (-not $seen.Add($name) -or $name -notmatch '\A[A-Za-z0-9_-]+(?:[./][A-Za-z0-9_-]+)*\z' -or
                ($entry.ExternalAttributes -band 0x400) -ne 0 -or (($entry.ExternalAttributes -shr 16) -band 0xF000) -notin @(0,0x8000)) {
                throw 'Unsafe, linked or duplicate archive entry.'
            }
            $total += $entry.Length
            if ($entry.Length -gt 134217728 -or $total -gt 268435456) { throw 'Archive payload exceeds size limit.' }
            if ($name -ceq 'emudhraslop.exe') { $binary = $entry }
        }
        if (-not $binary -or $binary.Length -lt 64) { throw 'Archive has no executable.' }
        $source = $binary.Open(); $output = $null
        try {
            $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $buffer = New-Object byte[] 65536; [long]$total = 0
            while (($read = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $total += $read
                if ($total -gt $binary.Length) { throw 'Executable exceeds declared size.' }
                $output.Write($buffer, 0, $read)
            }
            if ($total -ne $binary.Length) { throw 'Truncated executable.' }
        } finally { if ($output) { $output.Dispose() }; $source.Dispose() }
        $reader = [IO.BinaryReader]::new([IO.File]::OpenRead($Destination))
        try {
            if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'Invalid Windows executable.' }
            $reader.BaseStream.Position = 60; $offset = $reader.ReadUInt32()
            if ($offset -gt $reader.BaseStream.Length - 6) { throw 'Invalid PE offset.' }
            $reader.BaseStream.Position = $offset
            $machine = if ($Arch -eq 'amd64') { 0x8664 } else { 0xAA64 }
            if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne $machine) { throw 'Executable architecture mismatch.' }
        } finally { $reader.Dispose() }
    } finally { $zip.Dispose(); $inputFile.Dispose() }
}

function Install-Emudhraslop([string]$RequestedVersion, [string]$Destination) {
    Initialize-Installer
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Open a normal PowerShell window; installation does not need Administrator.' }
    if ($RequestedVersion) { Assert-Version $RequestedVersion }
    if (-not $Destination) { $Destination = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'emudhraslop\bin' }
    $lease = $null; $stage = $null
    $oldProtocol = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = $oldProtocol -bor [Net.SecurityProtocolType]::Tls12
        $lease = [EmudhraslopInstall.Native]::LockDirectory($Destination)
        $stage = [IO.Path]::Combine($lease.Path, ('.install-' + [guid]::NewGuid().ToString('N')))
        [EmudhraslopInstall.Native]::PrivateDirectory($stage)
        if (-not $RequestedVersion) {
            $metadata = [IO.Path]::Combine($stage, 'release.json')
            Receive-ReleaseFile 'https://api.github.com/repos/cowsecurity/emudhraslop/releases/latest' $metadata 65536
            $release = [IO.File]::ReadAllText($metadata) | ConvertFrom-Json
            if ($release.tag_name -cnotmatch '\Av(.+)\z') { throw 'Invalid release version.' }
            $RequestedVersion = $Matches[1]; Assert-Version $RequestedVersion
        }
        $arch = [EmudhraslopInstall.Native]::Architecture()
        $name = "emudhraslop-$RequestedVersion-windows-$arch.zip"
        $base = 'https://github.com/cowsecurity/emudhraslop/releases/download/v' + [uri]::EscapeDataString($RequestedVersion)
        $archive = [IO.Path]::Combine($stage, 'release.zip'); $checksums = [IO.Path]::Combine($stage, 'SHA256SUMS')
        Receive-ReleaseFile "$base/SHA256SUMS" $checksums 65536
        Receive-ReleaseFile "$base/$([uri]::EscapeDataString($name))" $archive 67108864
        Assert-ArchiveHash $checksums $archive $name
        $candidate = [IO.Path]::Combine($stage, 'emudhraslop.exe')
        Expand-Executable $archive $candidate $arch
        $target = [IO.Path]::Combine($lease.Path, 'emudhraslop.exe')
        if ([IO.File]::Exists($target)) {
            if (([IO.File]::GetAttributes($target) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Existing executable is a reparse point.' }
            [IO.File]::Replace($candidate, $target, $null)
        } else { [IO.File]::Move($candidate, $target) }
        $display = (Join-Path $Destination 'emudhraslop.exe').Replace("'", "''")
        Write-Host "Installed emudhraslop $RequestedVersion. Run:"
        Write-Host "  & '$display' check --online"
        Write-Host "For agents:"
        Write-Host "  & '$display' check --online --agent"
        Write-Host 'PATH was not changed. No scan has run.'
    } finally {
        if ($stage -and [IO.Directory]::Exists($stage)) { [IO.Directory]::Delete($stage, $true) }
        if ($lease) { $lease.Dispose() }
        [Net.ServicePointManager]::SecurityProtocol = $oldProtocol
    }
}

Install-Emudhraslop $Version $BinDir
