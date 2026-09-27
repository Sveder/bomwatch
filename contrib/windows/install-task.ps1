# Registers a scheduled task that runs a bomwatch scan and diff every 15
# minutes as the current user, and writes what changed to a log file.
#   powershell -ExecutionPolicy Bypass -File install-task.ps1
$bomwatch = (Get-Command bomwatch -ErrorAction Stop).Source
$log = Join-Path $env:LOCALAPPDATA "bomwatch\changes.log"
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
$command = "& '$bomwatch' scan | Out-Null; & '$bomwatch' diff --vulns | Add-Content -Path '$log'"
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -Command $command"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 15)
Register-ScheduledTask -TaskName "bomwatch" -Action $action -Trigger $trigger `
    -Description "bomwatch: report new software on this machine" -Force
Write-Host "bomwatch task registered; changes go to $log"
