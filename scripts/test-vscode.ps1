param([string]$CodeCli = (Join-Path $PSScriptRoot '..\.tools\vscode-portable\bin\code.cmd'))
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$profile = Join-Path $root '.tools\vscode-integration'
$settings = Join-Path $profile 'User'
New-Item -ItemType Directory -Force $settings | Out-Null
'{"telemetry.telemetryLevel":"off","update.mode":"none","extensions.autoUpdate":false,"extensions.autoCheckUpdates":false,"workbench.startupEditor":"none"}' | Set-Content -LiteralPath (Join-Path $settings 'settings.json') -Encoding UTF8
if (-not (Test-Path -LiteralPath $CodeCli)) { throw 'Specify an installed VS Code CLI or prepare the official ZIP in .tools/vscode-portable.' }
$runner = Join-Path $root 'test\vscode-runner.js'
$extensions = Join-Path $root '.tools\vscode-extensions'
$fixture = Join-Path $root '.tools\vulnerable-live'
& $CodeCli --new-window --wait --disable-gpu "--extensionDevelopmentPath=$root" "--extensionTestsPath=$runner" "--user-data-dir=$profile" "--extensions-dir=$extensions" --disable-extensions --skip-welcome --skip-release-notes --disable-workspace-trust $fixture
if ($LASTEXITCODE -ne 0) { throw 'VS Code extension host checks failed' }
if (-not (Test-Path -LiteralPath (Join-Path $root 'reports\vscode-summary.json'))) { throw 'VS Code did not produce the integration summary' }
Get-Content -LiteralPath (Join-Path $root 'reports\vscode-summary.json')
