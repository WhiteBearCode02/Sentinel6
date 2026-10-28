param([string]$CodeCli = (Join-Path $PSScriptRoot '..\.tools\vscode-portable\bin\code.cmd'))
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$profile=Join-Path $root '.tools\vscode-impact-integration'
$settings=Join-Path $profile 'User'
New-Item -ItemType Directory -Force $settings | Out-Null
# Explicit test-profile opt-in; collection is OFF and only synthetic fixtures are seeded.
$config='{"telemetry.telemetryLevel":"off","update.mode":"none","extensions.autoUpdate":false,"extensions.autoCheckUpdates":false,"workbench.startupEditor":"none","sentinel6.threatMonitoring.enabled":false,"sentinel6.projectAnalysis.enabled":true}'
[IO.File]::WriteAllText((Join-Path $settings 'settings.json'),$config,[Text.UTF8Encoding]::new($false))
& node (Join-Path $root 'scripts\prepare-impact-vscode.js')
if($LASTEXITCODE -ne 0){throw 'Synthetic fixture preparation failed'}
$summary=Join-Path $root 'reports\impact-vscode-summary.json'
if(Test-Path -LiteralPath $summary){Remove-Item -LiteralPath $summary}
$runner=Join-Path $root 'test\vscode-impact-runner.js'
$extensions=Join-Path $root '.tools\vscode-extensions'
$fixture=Join-Path $root '.tools\impact-fixture'
& $CodeCli --new-window --wait --disable-gpu "--extensionDevelopmentPath=$root" "--extensionTestsPath=$runner" "--user-data-dir=$profile" "--extensions-dir=$extensions" --disable-extensions --skip-welcome --skip-release-notes --disable-workspace-trust $fixture
if($LASTEXITCODE -ne 0){throw 'Project Impact integration checks failed'}
if(-not (Test-Path -LiteralPath $summary)){throw 'Project Impact summary not produced'}
Get-Content -LiteralPath $summary -Encoding UTF8
