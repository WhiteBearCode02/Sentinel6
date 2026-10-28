param([string]$CodeCli = (Join-Path $PSScriptRoot '..\.tools\vscode-portable\bin\code.cmd'))
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$profile=Join-Path $root '.tools\vscode-ti3-integration'
$settings=Join-Path $profile 'User'
New-Item -ItemType Directory -Force $settings | Out-Null
$config='{"telemetry.telemetryLevel":"off","update.mode":"none","extensions.autoUpdate":false,"extensions.autoCheckUpdates":false,"workbench.startupEditor":"none","sentinel6.threatMonitoring.enabled":false,"sentinel6.projectAnalysis.enabled":true,"sentinel6.securityNews.enabled":false}'
[IO.File]::WriteAllText((Join-Path $settings 'settings.json'),$config,[Text.UTF8Encoding]::new($false))
& node (Join-Path $root 'scripts\prepare-intelligence-vscode.js')
if($LASTEXITCODE -ne 0){throw 'Synthetic TI-3 preparation failed'}
$summary=Join-Path $root 'reports\intelligence-vscode-summary.json'
if(Test-Path -LiteralPath $summary){Remove-Item -LiteralPath $summary}
$runner=Join-Path $root 'test\vscode-intelligence-runner.js'
$extensions=Join-Path $root '.tools\vscode-extensions'
$fixture=Join-Path $root '.tools\ti3-fixture'
& $CodeCli --new-window --wait --disable-gpu "--extensionDevelopmentPath=$root" "--extensionTestsPath=$runner" "--user-data-dir=$profile" "--extensions-dir=$extensions" --disable-extensions --skip-welcome --skip-release-notes --disable-workspace-trust $fixture
if($LASTEXITCODE -ne 0){throw 'TI-3 extension-host checks failed'}
if(-not (Test-Path -LiteralPath $summary)){throw 'TI-3 summary missing'}
Get-Content -LiteralPath $summary -Encoding UTF8
