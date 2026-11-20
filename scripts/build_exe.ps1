# Build the Windows executable and assemble release artifacts (PowerShell).
#
# Usage (from anywhere):   powershell -File scripts/build_exe.ps1
# Requires: python -m pip install -r requirements-dev.txt
#
# Output (all git-ignored):
#   dist/IGMP-FLOW.exe
#   dist/IGMP-FLOW-v<version>/                   exe + manuals + license files + RELEASE_INFO.txt
#   dist/IGMP-FLOW-v<version>-windows.zip        the folder above (this is the file to attach to a GitHub Release)
#   dist/IGMP-FLOW-v<version>-source.zip         `git archive` of HEAD (only if the repository has a commit)
#   dist/SHA256SUMS.txt                          checksums of the zip files
#
# Scapy is GPL-2.0, so redistributing the exe means shipping the license texts and making the matching source available:
# publish the source zip (or the tagged repository) on the same release page.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $version = (python -c "from backend.constants import APP_VERSION; print(APP_VERSION)").Trim()
    if (-not $version) { throw "Could not read APP_VERSION" }
    $name = "IGMP-FLOW-v$version"

    python -m PyInstaller --noconfirm --clean --onefile --noconsole `
        --name IGMP-FLOW --icon assets\icon.ico `
        --add-data "frontend;frontend" `
        --hidden-import scapy.contrib.igmp --collect-submodules websockets `
        app.py
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE" }

    # --- assemble the release folder -------------------------------------------------------------
    $stage = Join-Path 'dist' $name
    if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
    New-Item -ItemType Directory -Force $stage | Out-Null
    Copy-Item 'dist\IGMP-FLOW.exe' $stage
    foreach ($f in 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'README.md', 'README_JP.md') { Copy-Item $f $stage }
    Copy-Item -Recurse 'licenses' (Join-Path $stage 'licenses')
    Copy-Item -Recurse 'docs' (Join-Path $stage 'docs')

    $exeHash = (Get-FileHash (Join-Path $stage 'IGMP-FLOW.exe') -Algorithm SHA256).Hash.ToLower()
    $info = @(
        "IGMP-FLOW $version",
        "Built: $(Get-Date -Format 'yyyy-MM-dd')",
        "IGMP-FLOW.exe SHA-256: $exeHash",
        "",
        "Before you start:",
        "  1. Install Npcap (https://npcap.com/) - it is NOT included. See docs/manual_EN.md or docs/manual_JP.md.",
        "  2. Run IGMP-FLOW.exe (as administrator if capture does not start).",
        "",
        "License: MIT for IGMP-FLOW's own code (LICENSE). This executable bundles Scapy (GPL-2.0), so it is",
        "distributed under GPL-2.0 terms; see THIRD_PARTY_NOTICES.md and licenses/.",
        "Corresponding source: IGMP-FLOW-v$version-source.zip on the same release page, or the tagged repository."
    )
    Set-Content -Path (Join-Path $stage 'RELEASE_INFO.txt') -Value $info -Encoding UTF8

    # --- zip files --------------------------------------------------------------------------------
    # Use Python's zipfile: Windows PowerShell 5.1's Compress-Archive writes backslashes into entry names,
    # which breaks extraction on macOS/Linux and in some tools.
    $zip = "dist\$name-windows.zip"
    if (Test-Path $zip) { Remove-Item -Force $zip }
    Push-Location 'dist'
    try { python -m zipfile -c "$name-windows.zip" $name } finally { Pop-Location }
    if (-not (Test-Path $zip)) { throw "Failed to create $zip" }

    $sums = @()
    $sums += "$((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower())  $name-windows.zip"

    git rev-parse --verify HEAD 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $src = "dist\$name-source.zip"
        if (Test-Path $src) { Remove-Item -Force $src }
        git archive --format=zip --prefix="$name/" -o $src HEAD
        $sums += "$((Get-FileHash $src -Algorithm SHA256).Hash.ToLower())  $name-source.zip"
    } else {
        Write-Warning "No git commit yet: the source zip was not created."
    }
    Set-Content -Path 'dist\SHA256SUMS.txt' -Value $sums -Encoding ASCII

    Write-Host "Built:   dist\IGMP-FLOW.exe"
    Write-Host "Release: $zip"
    $sums | ForEach-Object { Write-Host "  $_" }
}
finally {
    Pop-Location
}
