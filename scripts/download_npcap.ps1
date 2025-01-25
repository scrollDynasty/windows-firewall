# Скрипт для загрузки Npcap SDK
$npcapSdkUrl = "https://npcap.com/dist/npcap-sdk-1.12.zip"
$downloadPath = "$PSScriptRoot\..\extern"
$npcapPath = "$downloadPath\npcap"

# Создаем директории
New-Item -ItemType Directory -Force -Path $downloadPath
New-Item -ItemType Directory -Force -Path $npcapPath

# Загружаем Npcap SDK
$sdkZip = "$downloadPath\npcap-sdk.zip"
Invoke-WebRequest -Uri $npcapSdkUrl -OutFile $sdkZip

# Распаковываем SDK
Expand-Archive -Path $sdkZip -DestinationPath $npcapPath -Force

# Очищаем временные файлы
Remove-Item $sdkZip

Write-Host "Npcap SDK downloaded and extracted successfully!"