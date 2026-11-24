param([string]$ToolchainRoot="C:\Strawberry\c")
$ErrorActionPreference="Stop"
$repo = Split-Path -Parent $PSScriptRoot
$sourceDir = Join-Path $repo "vendor\pbc-1.0.0"
$archive = Join-Path $repo "vendor\pbc-1.0.0.tar.gz"
if (-not (Test-Path -LiteralPath $sourceDir)) {
  New-Item -ItemType Directory -Path (Join-Path $repo "vendor") -Force | Out-Null
  Invoke-WebRequest "https://crypto.stanford.edu/pbc/files/pbc-1.0.0.tar.gz" -OutFile $archive
  if ((Get-FileHash -LiteralPath $archive).Hash -ne "18275A367283077BAFE35F443200499E3B19C4A3754953DA2A1B2F0D6B5922DC") {
    throw "PBC source checksum mismatch"
  }
  tar -xzf $archive -C (Join-Path $repo "vendor")
}
$buildSource=$repo
if ($repo -match '[^\x00-\x7F]') {
  $digest=[Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($repo))
  $short=[BitConverter]::ToString($digest).Replace('-','').Substring(0,12)
  $buildSource=Join-Path $env:TEMP ("otac-pbc-"+$short)
  $existingAlias=Join-Path $env:TEMP "otac-pbc-source"
  if (Test-Path -LiteralPath $existingAlias) {
    $existingItem=Get-Item -LiteralPath $existingAlias
    if ($existingItem.LinkType -eq "Junction" -and $existingItem.Target[0] -eq $repo) {
      $buildSource=$existingAlias
    }
  }
  if (-not (Test-Path -LiteralPath $buildSource)) {
    New-Item -ItemType Junction -Path $buildSource -Target $repo | Out-Null
  }
  $aliasItem=Get-Item -LiteralPath $buildSource
  if ($aliasItem.LinkType -ne "Junction" -or $aliasItem.Target[0] -ne $repo) {
    throw "ASCII build alias does not point to this repository"
  }
}
$env:GMP_ROOT=$ToolchainRoot
$env:OPENSSL_ROOT_DIR=$ToolchainRoot
$env:PATH=(Join-Path $ToolchainRoot "bin")+";"+$env:PATH
cmake -S $buildSource -B (Join-Path $buildSource "build-native") -G "MinGW Makefiles" "-DCMAKE_C_COMPILER=$ToolchainRoot/bin/gcc.exe" "-DCMAKE_CXX_COMPILER=$ToolchainRoot/bin/g++.exe"
if ($LASTEXITCODE) { throw "CMake configuration failed" }
cmake --build (Join-Path $buildSource "build-native") --parallel 6
if ($LASTEXITCODE) { throw "Build failed" }
