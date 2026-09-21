# POC-Recon Windows One-Line PowerShell Installer
$ErrorActionPreference = "Stop"

$repo = "zaidkhan0997/POC-Recon"
$installDir = "$env:LOCALAPPDATA\Programs\POC-Recon"
$assetName = "poc-recon-windows-x64.exe"
$downloadUrl = "https://github.com/$repo/releases/latest/download/$assetName"
$destPath = "$installDir\poc-recon.exe"

Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "     Installing POC-Recon for Windows   " -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan

if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

Write-Host "[*] Downloading: $downloadUrl" -ForegroundColor Yellow
Invoke-WebRequest -Uri $downloadUrl -OutFile $destPath -UseBasicParsing

# Add to user PATH if not present
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$installDir*") {
    Write-Host "[*] Adding $installDir to User PATH..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$installDir", "User")
    $env:Path = "$env:Path;$installDir"
}

# Create Desktop Shortcut
$desktop = [Environment]::GetFolderPath("Desktop")
$shortcutPath = "$desktop\POC-Recon.lnk"
$wsh = New-Object -ComObject WScript.Shell
$shortcut = $wsh.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $destPath
$shortcut.WorkingDirectory = $installDir
$shortcut.Description = "POC-Recon: Business Email Discovery & Verification"
$shortcut.Save()

Write-Host "[✔] Successfully installed!" -ForegroundColor Green
Write-Host " - Executable: $destPath" -ForegroundColor White
Write-Host " - Desktop shortcut created!" -ForegroundColor White
Write-Host ""
Write-Host "You can now run POC-Recon by typing 'poc-recon' or clicking the desktop shortcut." -ForegroundColor Cyan
