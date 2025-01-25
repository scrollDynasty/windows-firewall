$winpcapUrl = "https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe"
$winpcapDevUrl = "https://www.winpcap.org/install/bin/WpdPack_4_1_3.zip"
$downloadPath = "$PSScriptRoot\..\extern"

New-Item -ItemType Directory -Force -Path $downloadPath

$installer = "$downloadPath\WinPcap_4_1_3.exe"
Invoke-WebRequest -Uri $winpcapUrl -OutFile $installer

$devpack = "$downloadPath\WpdPack_4_1_3.zip"
Invoke-WebRequest -Uri $winpcapDevUrl -OutFile $devpack

Start-Process -FilePath $installer -ArgumentList "/S" -Wait

Expand-Archive -Path $devpack -DestinationPath "$downloadPath\WinPcap" -Force

Write-Host "WinPcap installation complete!"