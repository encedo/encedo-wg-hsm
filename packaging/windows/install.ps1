# Installs the Encedo WireGuard client: both halves, the driver, the service and
# a shortcut. Run from an elevated PowerShell, in the directory this file is in.
#
#     powershell -ExecutionPolicy Bypass -File install.ps1
#
# The Linux counterpart is a .deb, and this is deliberately the same shape: it
# places files, registers a service that starts on demand, and adds one entry to
# the menu. It does not start a tunnel. Nothing here brings one up at boot: the
# service exists so that a person opening the window does not have to be an
# administrator, not so that a tunnel exists without one.
#
# It is a script rather than an MSI because an MSI needs a toolchain on the build
# machine to produce and gives, for this, nothing a script does not: there is no
# component to register, no COM, no upgrade table worth having yet. That changes
# the day this is signed and handed to somebody who is not a developer.

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$source  = $PSScriptRoot
$target  = Join-Path $env:ProgramFiles 'Encedo WG'
$service = 'encedo-wg'

# Named rather than globbed. A glob here is how the wrong record dialect gets
# installed: the 64-byte and 128-byte builds differ by a suffix, they cannot read
# each other's configuration, and the failure reads as a corrupt tree rather than
# as a mismatched binary.
$files = @('wg-hem.exe', 'encedo-wg-gui.exe', 'wintun.dll')

foreach ($f in $files) {
    if (-not (Test-Path (Join-Path $source $f))) {
        throw "$f is missing from $source. Unpack the whole bundle before running this."
    }
}

# The two halves refuse each other unless their stamps match, and a bundle
# assembled by hand from two downloads is how they come to differ. Checked here
# rather than discovered later by somebody who has already typed a passphrase.
# Through a file, not through the pipeline, and the reason is the window rather
# than the client. encedo-wg-gui.exe is linked for the GUI subsystem so that no
# console appears behind it, and what a process in that subsystem does with its
# output when a shell runs it is not something to rely on: `& gui.exe -version`
# captured nothing here twice, once because the program wrote to the console
# device and once because the shell did not collect what it wrote.
#
# Start-Process -Wait -RedirectStandardOutput takes both questions out of it. The
# file is a handle the program is given, so it writes there; -Wait means the
# answer is on disk before it is read, whatever subsystem the program was linked
# for.
function Get-Stamp {
    param([string]$Exe, [string[]]$VersionArgs, [string]$Prefix)

    $out = New-TemporaryFile
    try {
        Start-Process -FilePath $Exe -ArgumentList $VersionArgs `
            -RedirectStandardOutput $out -NoNewWindow -Wait | Out-Null
        $text = (Get-Content -Raw -ErrorAction SilentlyContinue $out)
    } finally {
        Remove-Item -Force -ErrorAction SilentlyContinue $out
    }
    if (-not $text) { return '' }
    return ($text.Trim() -replace "^$Prefix\s+", '')
}

$hemStamp = Get-Stamp (Join-Path $source 'wg-hem.exe')        @('version')  'wg-hem'
$guiStamp = Get-Stamp (Join-Path $source 'encedo-wg-gui.exe') @('-version') 'encedo-wg-gui'
# A stamp that cannot be read is a warning; two stamps that disagree is a
# refusal. The distinction is the point.
#
# A mismatched pair is the thing worth stopping for: it fails later, after a
# passphrase, and confusingly. Not being able to read a version is a fault in
# this check rather than in what is being installed, and this check has now
# blocked the installation three times over its own difficulty reading a
# GUI-subsystem program. A guard that stops the work it exists to protect is
# worse than no guard.
if (-not $hemStamp -or -not $guiStamp) {
    Write-Warning @"
Could not read a version from both halves, so they were not compared:
  wg-hem.exe          $(if ($hemStamp) { $hemStamp } else { '(nothing)' })
  encedo-wg-gui.exe   $(if ($guiStamp) { $guiStamp } else { '(nothing)' })
Installing anyway. If the two do not match, the window will say so when it tries
to connect, and "wg-hem probe" prints both.
"@
} elseif ($hemStamp -ne $guiStamp) {
    throw @"
These two halves will refuse to drive each other:
  wg-hem.exe          $hemStamp
  encedo-wg-gui.exe   $guiStamp
Take both from one build.
"@
}

Write-Host "Installing $(if ($hemStamp) { $hemStamp } else { 'an unknown build' })"

if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
    Write-Host 'Stopping the existing service...'
    & (Join-Path $target 'wg-hem.exe') service stop 2>$null
    & (Join-Path $target 'wg-hem.exe') service uninstall 2>$null
}

New-Item -ItemType Directory -Force -Path $target | Out-Null
foreach ($f in $files) {
    Copy-Item -Force (Join-Path $source $f) (Join-Path $target $f)
}
Write-Host "Placed in $target"

# Registered against the installed copy, not the one just unpacked: a service
# whose path points into a downloads folder works until that folder is tidied.
& (Join-Path $target 'wg-hem.exe') service install
& (Join-Path $target 'wg-hem.exe') service start

# The shortcut takes no arguments. The window drives a real appliance when asked
# for nothing, which is the whole reason that default was turned round. A Start
# menu entry that launched the scripted stand-in would be a menu entry that lies.
$menu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\encedo-wg.lnk'
$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut($menu)
$link.TargetPath = Join-Path $target 'encedo-wg-gui.exe'
$link.WorkingDirectory = $target
$link.Description = 'A WireGuard tunnel whose private key never leaves the module'
$link.Save()

Write-Host @"

Done. Open "encedo-wg" from the Start menu.

The service is running and waiting for a window; it holds no credential and
brings nothing up on its own. Closing the window ends the tunnel.

To check the two halves can see each other:  "$target\wg-hem.exe" probe
To remove all of it:                         uninstall.ps1
"@
