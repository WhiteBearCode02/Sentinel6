param([string]$CodeCli = (Join-Path $PSScriptRoot '..\.tools\vscode-portable\bin\code.cmd'))
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$profile=Join-Path $root '.tools\vscode-threat-integration'
$user=Join-Path $profile 'User'
$global=Join-Path $user 'globalStorage\sentinel6-local.sentinel6'
New-Item -ItemType Directory -Force $global | Out-Null
$config='{"telemetry.telemetryLevel":"off","update.mode":"none","extensions.autoUpdate":false,"extensions.autoCheckUpdates":false,"workbench.startupEditor":"none","sentinel6.threatMonitoring.enabled":false}'
[IO.File]::WriteAllText((Join-Path $user 'settings.json'),$config,[Text.UTF8Encoding]::new($false))
$summary=Join-Path $root 'reports\threat-vscode-summary.json'
if(Test-Path -LiteralPath $summary){Remove-Item -LiteralPath $summary}
# Seed only real public data collected by the live verification; never mock discoveries.
Copy-Item -LiteralPath (Join-Path $root 'reports\threat-live-verified\threat-intelligence.sqlite') -Destination (Join-Path $global 'threat-intelligence.sqlite') -Force
$runner=Join-Path $root 'test\vscode-threat-runner.js'
$extensions=Join-Path $root '.tools\vscode-extensions'
$fixture=Join-Path $root '.tools\vulnerable-live'
& $CodeCli --new-window --wait --disable-gpu "--extensionDevelopmentPath=$root" "--extensionTestsPath=$runner" "--user-data-dir=$profile" "--extensions-dir=$extensions" --disable-extensions --skip-welcome --skip-release-notes --disable-workspace-trust $fixture
if($LASTEXITCODE -ne 0){throw 'Threat Feed integration checks failed'}
if(-not (Test-Path -LiteralPath (Join-Path $root 'reports\threat-vscode-summary.json'))){throw 'Threat Feed summary not produced'}
Get-Content -LiteralPath (Join-Path $root 'reports\threat-vscode-summary.json') -Encoding UTF8
