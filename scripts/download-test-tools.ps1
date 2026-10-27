$ErrorActionPreference = 'Stop'
$base = Join-Path $PSScriptRoot '..\.tools'
New-Item -ItemType Directory -Force $base | Out-Null
$items = @(
  @{ Repo='gitleaks/gitleaks'; Tag='v8.30.1'; Asset='gitleaks_8.30.1_windows_x64.zip'; Sums='gitleaks_8.30.1_checksums.txt'; Dir='gitleaks' },
  @{ Repo='google/osv-scanner'; Tag='v2.7.0'; Asset='osv-scanner_windows_amd64.exe'; Sums='osv-scanner_SHA256SUMS'; Dir='osv' },
  @{ Repo='aquasecurity/trivy'; Tag='v0.76.1'; Asset='trivy_0.76.1_windows-64bit.zip'; Sums='trivy_0.76.1_checksums.txt'; Dir='trivy' }
)
foreach ($item in $items) {
  $url = "https://github.com/$($item.Repo)/releases/download/$($item.Tag)"
  $archive = Join-Path $base $item.Asset
  $sums = Join-Path $base $item.Sums
  Invoke-WebRequest "$url/$($item.Asset)" -OutFile $archive -UseBasicParsing
  Invoke-WebRequest "$url/$($item.Sums)" -OutFile $sums -UseBasicParsing
  $expected = (Get-Content -LiteralPath $sums | Where-Object { $_ -match ([regex]::Escape($item.Asset) + '$') })
  if (-not $expected -or $expected.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)[0].ToLower() -ne (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLower()) { throw 'Checksum mismatch' }
  $dest = Join-Path $base $item.Dir
  New-Item -ItemType Directory -Force $dest | Out-Null
  if ($item.Asset.EndsWith('.zip')) { Expand-Archive -LiteralPath $archive -DestinationPath $dest -Force }
  else { Copy-Item -LiteralPath $archive -Destination (Join-Path $dest 'osv-scanner.exe') }
  Write-Output "$($item.Dir): checksum verified"
}
