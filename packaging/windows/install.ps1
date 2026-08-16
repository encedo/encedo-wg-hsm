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
$hemVersion = (& (Join-Path $source 'wg-hem.exe') version) -join ''
$guiVersion = (& (Join-Path $source 'encedo-wg-gui.exe') -version) -join ''
$hemStamp = ($hemVersion -replace '^wg-hem\s+', '')
$guiStamp = ($guiVersion -replace '^encedo-wg-gui\s+', '')
# Said separately, because "it printed nothing" and "it printed something else"
# are different faults and the second reads as the first when the column is
# blank. A window built for the GUI subsystem has no console to print to, which
# is exactly how this failed once: the halves matched and the comparison could
# not see it.
if (-not $hemStamp) { throw "wg-hem.exe printed no version. Is it the right file?" }
if (-not $guiStamp) {
    throw @"
encedo-wg-gui.exe printed no version.
It is linked for the GUI subsystem and has to attach to this console to print at
all, so a build from before that was fixed cannot report its version and this
installer cannot check the pair. Take a newer build.
"@
}
if ($hemStamp -ne $guiStamp) {
    throw @"
These two halves will refuse to drive each other:
  wg-hem.exe          $hemStamp
  encedo-wg-gui.exe   $guiStamp
Take both from one build.
"@
}
Write-Host "Installing $hemStamp"

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
