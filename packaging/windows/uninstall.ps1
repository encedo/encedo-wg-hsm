# Removes what install.ps1 placed. Elevated PowerShell:
#
#     powershell -ExecutionPolicy Bypass -File uninstall.ps1
#
# Ordered so that nothing is left holding anything: the tunnel goes with the
# service, the service goes before its executable, and the executable goes last.
# Each step tolerates its subject already being absent, because the common reason
# to run this is that a previous attempt stopped halfway.

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$target  = Join-Path $env:ProgramFiles 'Encedo WG'
$service = 'encedo-wg'
$hem     = Join-Path $target 'wg-hem.exe'
$menu    = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\encedo-wg.lnk'

# The window holds the tunnel: the component gives it to whoever opened the
# connection and takes it back when they go. Stopping the service therefore ends
# any tunnel with it, and there is nothing else to unwind.
if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
    if (Test-Path $hem) {
        & $hem service stop 2>$null
        & $hem service uninstall 2>$null
    } else {
        # The executable is gone but the registration is not, which is what a
        # half-finished removal leaves. sc.exe can still undo it.
        Write-Warning "$hem is missing; removing the service registration directly"
        & sc.exe stop $service | Out-Null
        & sc.exe delete $service | Out-Null
    }
    Write-Host 'Service removed.'
}

if (Test-Path $menu) { Remove-Item -Force $menu; Write-Host 'Shortcut removed.' }

# The name notifications were sent under. Left behind it would point at an icon
# that no longer exists, which is how a notification comes to have a blank
# square where a mark was.
$aumid = 'HKLM:\SOFTWARE\Classes\AppUserModelId\com.encedo.wg'
if (Test-Path $aumid) {
    Remove-Item -Path $aumid -Recurse -Force
    Write-Host 'Notification name removed.'
}

if (Test-Path $target) {
    # Retried once: Windows can hold a file open for a moment after the process
    # using it exits, and failing here would leave the caller with a service
    # already gone and files they have to delete by hand.
    try {
        Remove-Item -Recurse -Force $target
    } catch {
        Start-Sleep -Seconds 2
        Remove-Item -Recurse -Force $target
    }
    Write-Host "Removed $target"
}

Write-Host @"

Done.

Left behind on purpose: nothing this program wrote to %ProgramData%\WireGuard,
which is where a running interface leaves its state, and the window's own
settings under HKCU. Neither is a secret (no key material is written anywhere
by either half), and both are what somebody reinstalling would want kept.
"@
