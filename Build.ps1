clear
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Start-Process powershell.exe -ArgumentList " -NoProfile -ExecutionPolicy Bypass -File $($MyInvocation.MyCommand.Path)" -Verb RunAs; exit }
$ScriptVersion = "v2.5.1"
[System.Console]::Title = "Enterprise G Reconstruction $ScriptVersion"
Set-Location -Path $PSScriptRoot

$requiredWIM = @("install.wim")
$missingWIM = $requiredWIM | Where-Object { -not (Test-Path $_) }
if ($missingWIM) { [System.Media.SystemSounds]::Asterisk.Play(); Write-Host "$([char]0x1b)[48;2;255;0;0m=== Install.wim could not be found."; pause; exit }

$imageInfo = Get-WindowsImage -ImagePath "install.wim" -index:1
$Build = $imageInfo.Version
$detectedBuild = [int]($Build -replace '1[0-9]\.\d+\.', '')

function Download-Files {
    param (
        [string]$buildUri,
        [string]$editionUri
    )
    $webClient = New-Object Net.WebClient
    Write-Host "$([char]0x1b)[48;2;20;14;136m=== Downloading Language Pack"
    Write-Host
    $webClient.DownloadFile($buildUri, "$PSScriptRoot\Microsoft-Windows-Client-LanguagePack-Package-amd64-en-us.esd")
    Write-Host "$([char]0x1b)[48;2;20;14;136m=== Downloading Edition Files"
    $webClient.DownloadFile($editionUri, "$PSScriptRoot\Microsoft-Windows-EditionSpecific-EnterpriseG-Package.ESD")
    cls 
}

switch ($detectedBuild) {
    26120 { Download-Files "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/26100/Microsoft-Windows-Client-LanguagePack-Package-amd64-en-us.esd" "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/26100/Microsoft-Windows-EditionSpecific-EnterpriseG-Package.ESD" }
    26100 { Download-Files "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/26100/Microsoft-Windows-Client-LanguagePack-Package-amd64-en-us.esd" "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/26100/Microsoft-Windows-EditionSpecific-EnterpriseG-Package.ESD" }
    22635 { Download-Files "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/226x1/Microsoft-Windows-Client-LanguagePack-Package_en-us-amd64-en-us.esd" "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/226x1/Microsoft-Windows-EditionSpecific-EnterpriseG-Package.ESD" }
    22631 { Download-Files "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/226x1/Microsoft-Windows-Client-LanguagePack-Package_en-us-amd64-en-us.esd" "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/226x1/Microsoft-Windows-EditionSpecific-EnterpriseG-Package.ESD" }
    22621 { Download-Files "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/226x1/Microsoft-Windows-Client-LanguagePack-Package_en-us-amd64-en-us.esd" "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/226x1/Microsoft-Windows-EditionSpecific-EnterpriseG-Package.ESD" }
    22000 { Download-Files "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/22000/Microsoft-Windows-Client-LanguagePack-Package_en-us-amd64-en-us.esd" "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/22000/Microsoft-Windows-EditionSpecific-EnterpriseG-Package.ESD" }
    19045 { Download-Files "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/19041/Microsoft-Windows-Client-LanguagePack-Package_en-us-amd64-en-us.esd" "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/19041/Microsoft-Windows-EditionSpecific-EnterpriseG-Package.ESD" }
    19044 { Download-Files "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/19041/Microsoft-Windows-Client-LanguagePack-Package_en-us-amd64-en-us.esd" "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/19041/Microsoft-Windows-EditionSpecific-EnterpriseG-Package.ESD" }
    19043 { Download-Files "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/19041/Microsoft-Windows-Client-LanguagePack-Package_en-us-amd64-en-us.esd" "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/19041/Microsoft-Windows-EditionSpecific-EnterpriseG-Package.ESD" }
    19042 { Download-Files "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/19041/Microsoft-Windows-Client-LanguagePack-Package_en-us-amd64-en-us.esd" "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/19041/Microsoft-Windows-EditionSpecific-EnterpriseG-Package.ESD" }
    19041 { Download-Files "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/19041/Microsoft-Windows-Client-LanguagePack-Package_en-us-amd64-en-us.esd" "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/19041/Microsoft-Windows-EditionSpecific-EnterpriseG-Package.ESD" }
    17763 { Download-Files "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/17763/Microsoft-Windows-Client-LanguagePack-Package_en-US-AMD64-en-us.esd" "https://github.com/TK50P/EnterpriseG-Reconstruction/releases/download/17763/Microsoft-Windows-EditionSpecific-EnterpriseG-Package.ESD" }
    default {
        Write-Host "$([char]0x1b)[48;2;255;0;0m=== This build of Windows is not officially supported for reconstruction. If you are trying to build Insider Preiew, edit this script."
        Write-Host "Supported builds: 17763 (1809), 19041 (2004), 19042 (20H2), 19043 (21H1), 19044 (10 21H2), 19045 (10 22H2) 22000 (21H2), 22621 (22H2 & 23H2), 22635 (23H2 Beta), 26100 (24H2) & 26120 (24H2 Dev)"
        Write-Host "Detected build: $detectedBuild"
        pause
        exit
    }
}

@("mount", "sxs") | ForEach-Object { if (!(Test-Path $_ -PathType Container)) { New-Item -Path $_ -ItemType Directory -Force   } }

$Windows = ($imageInfo.ImageName -split ' ')[1]
$ProIndex = Get-WindowsImage -ImagePath "install.wim" | Where-Object { $_.ImageName -eq "Windows $Windows Pro" } | Select-Object -ExpandProperty ImageIndex; if (-not $ProIndex) {  Write-Host "$([char]0x1b)[48;2;255;0;0m=== Install.wim does not contain Windows Pro Edition."; @("mount", "sxs") | ForEach-Object { Remove-Item $_ -Recurse -Force -ErrorAction SilentlyContinue }; pause; exit }
if ($imageInfo.SPBuild -notmatch "^1$") { [System.Media.SystemSounds]::Asterisk.Play(); Write-Host "$([char]0x1b)[48;2;255;0;0m=== Your Install.wim contains updates. UUPDump.net can help you make an ISO without." ; @("mount", "sxs") | ForEach-Object { Remove-Item $_ -Recurse -Force -ErrorAction SilentlyContinue }; pause; exit }

switch ($detectedBuild) {
    { $_ -lt 19041 } { $Type = "Legacy"; break }
    { $_ -lt 25398 } { $Type = "Normal"; break }
    default { $Type = "24H2" }
}

$config = (Get-Content "config.json" -Raw) | ConvertFrom-Json
$ActivateWindows = $config.ActivateWindows
$RemoveEdge = $config.RemoveEdge
$startTime = Get-Date
Write-Host "Enterprise G Reconstruction $ScriptVersion"
Write-Host
Write-Host "- Windows: $Windows"
Write-Host "- Build: $Build"
Write-Host "- Type: $Type"
Write-Host
Write-Host "- ActivateWindows: $ActivateWindows"
Write-Host "- RemoveEdge: $RemoveEdge"
Write-Host

Write-Host
Write-Host "$([char]0x1b)[48;2;20;14;136m=== Preparing Files"
$editionesd = (Get-ChildItem -Filter "Microsoft-Windows-EditionSpecific*.esd").Name
.\files\wimlib-imagex extract .\$editionesd 1 --dest-dir=sxs  
Remove-Item -Path .\$editionesd
$lpesd = (Get-ChildItem -Filter "Microsoft-Windows-Client-LanguagePack*.esd")
Move-Item -Path $lpesd.FullName -Destination .\sxs\  

Write-Host
Write-Host "$([char]0x1b)[48;2;20;14;136m=== Mounting Image"
Set-ItemProperty -Path "install.wim" -Name IsReadOnly -Value $false  
dism /Mount-Wim /WimFile:"install.wim" /Index:$ProIndex /MountDir:"mount"  

if ($Type -in "Normal", "24H2", "Legacy") {
    Copy-Item -Path "files\sxs\$Type\*.*" -Destination "sxs\" -Force

    Rename-Item -Path "sxs\Microsoft-Windows-EnterpriseGEdition~31bf3856ad364e35~amd64~~10.0.22621.1.mum" -NewName "Microsoft-Windows-EnterpriseGEdition~31bf3856ad364e35~amd64~~$Build.mum" -Force
    Rename-Item -Path "sxs\Microsoft-Windows-EnterpriseGEdition~31bf3856ad364e35~amd64~~10.0.22621.1.cat" -NewName "Microsoft-Windows-EnterpriseGEdition~31bf3856ad364e35~amd64~~$Build.cat" -Force

    (Get-Content "sxs\Microsoft-Windows-EnterpriseGEdition~31bf3856ad364e35~amd64~~$Build.mum") -replace '10\.0\.22621\.1', $Build | Set-Content "sxs\Microsoft-Windows-EnterpriseGEdition~31bf3856ad364e35~amd64~~$Build.mum" -Force
    (Get-Content "sxs\1.xml") -replace '10\.0\.22621\.1', $Build | Set-Content "sxs\1.xml" -Force
}

Write-Host
Write-Host "$([char]0x1b)[48;2;20;14;136m=== Converting Edition"
dism /image:mount /apply-unattend:sxs\1.xml  
Remove-Item -Path mount\Windows\*.xml -ErrorAction SilentlyContinue
Copy-Item -Path mount\Windows\servicing\Editions\EnterpriseGEdition.xml -Destination mount\Windows\EnterpriseG.xml -ErrorAction SilentlyContinue

Write-Host
Write-Host "$([char]0x1b)[48;2;20;14;136m=== Setting SKU to Enterprise G"
dism /image:mount /apply-unattend:mount\Windows\EnterpriseG.xml  
if ($Type -eq "24H2") {
    Dism /Image:mount /Set-Edition:EnterpriseG /AcceptEula /ProductKey:FV469-WGNG4-YQP66-2B2HY-KD8YX  
} else {
    Dism /Image:mount /Set-Edition:EnterpriseG /AcceptEula /ProductKey:YYVX9-NTFWV-6MDM3-9PT4T-4M68B  
}
$currentEdition = (dism /image:mount /get-currentedition | Out-String)

if ($currentEdition -match "EnterpriseG") {
    Write-Host
    Write-Host "$([char]0x1b)[48;2;20;14;136m=== SKU successfully updated to EnterpriseG"
} else {
    Write-Host
    Write-Host "$([char]0x1b)[48;2;255;0;0m=== Reconstruction failed. Undoing changes..."
    Write-Host
    Write-Host "$([char]0x1b)[48;2;20;14;136m=== Unmounting Install.wim"
    dism /unmount-wim /mountdir:mount /discard  
    Write-Host
    @("mount", "sxs") | ForEach-Object { if (Test-Path $_ -ErrorAction SilentlyContinue) { Remove-Item $_ -Recurse -Force -ErrorAction SilentlyContinue } }
    pause
    exit
}

Write-Host
Write-Host "$([char]0x1b)[48;2;20;14;136m=== Applying Registry Keys"
reg load HKLM\zSOFTWARE mount\Windows\System32\config\SOFTWARE  
reg load HKLM\zSYSTEM mount\Windows\System32\config\SYSTEM  
reg load HKLM\zNTUSER mount\Users\Default\ntuser.dat  
# Microsoft Account support
reg Add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Accounts" /v "AllowMicrosoftAccountSignInAssistant" /t REG_DWORD /d "1" /f  
# Producer branding
reg add "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion" /v EditionSubManufacturer /t REG_SZ /d "Microsoft Corporation" /f  
reg add "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion" /v EditionSubVersion /t REG_SZ /d "$ScriptVersion" /f  
# Fix Windows Security
reg add "HKLM\zSYSTEM\ControlSet001\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d 0 /f  
# Turn off Defender Updates
reg add "HKLM\zSOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "ForceUpdateFromMU" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "UpdateOnStartUp" /t REG_DWORD /d "0" /f  
# Hide settings pages
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "SettingsPageVisibility" /t REG_SZ /d "hide:activation;gaming-gamebar;gaming-gamedvr;gaming-gamemode;quietmomentsgame" /f  
# Turn off auto updates
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "ConfigureStartPins" /t REG_SZ /d '{\"pinnedList\": [{}]}' /f  
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSoftware\Policies\Microsoft\PushToInstall" /v "DisablePushToInstall" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v "ChatIcon" /t REG_DWORD /d "3" /f  
reg delete "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f  
reg delete "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f  
reg delete "HKLM\zSOFTWARE\policies\microsoft\windows\windowsupdate" /v "allowoptionalcontent" /f  
reg delete "HKLM\zSOFTWARE\policies\microsoft\windows\windowsupdate" /v "branchreadinesslevel" /f  
reg add "HKLM\zSOFTWARE\policies\microsoft\windows\windowsupdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\policies\microsoft\windows\windowsupdate" /v "ManagePreviewBuildsPolicyValue" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\policies\microsoft\windows\windowsupdate" /v "SetAllowOptionalContent" /t REG_DWORD /d "0" /f  
reg delete "HKLM\zSOFTWARE\policies\microsoft\windows\windowsupdate\au" /v "allowmuupdateservice" /f  
reg delete "HKLM\zSOFTWARE\policies\microsoft\windows\windowsupdate\au" /v "auoptions" /f  
reg delete "HKLM\zSOFTWARE\policies\microsoft\windows\windowsupdate\au" /v "automaticmaintenanceenabled" /f  
reg delete "HKLM\zSOFTWARE\policies\microsoft\windows\windowsupdate\au" /v "scheduledinstallday" /f  
reg delete "HKLM\zSOFTWARE\policies\microsoft\windows\windowsupdate\au" /v "scheduledinstalleveryweek" /f  
reg delete "HKLM\zSOFTWARE\policies\microsoft\windows\windowsupdate\au" /v "scheduledinstallfirstweek" /f  
reg delete "HKLM\zSOFTWARE\policies\microsoft\windows\windowsupdate\au" /v "scheduledinstallfourthweek" /f  
reg delete "HKLM\zSOFTWARE\policies\microsoft\windows\windowsupdate\au" /v "scheduledinstallsecondweek" /f  
reg delete "HKLM\zSOFTWARE\policies\microsoft\windows\windowsupdate\au" /v "scheduledinstallthirdweek" /f  
reg delete "HKLM\zSOFTWARE\policies\microsoft\windows\windowsupdate\au" /v "scheduledinstalltime" /f  
reg add "HKLM\zSOFTWARE\policies\microsoft\windows\windowsupdate\au" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d "2" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\WindowsStore" /v "DisableOSUpgrade" /t REG_DWORD /d "1" /f  
# Hide recommended section in Windows Start Menu
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecommendedSection" /t REG_DWORD /d "1" /f  
reg add "HKLM\zNTUSER\Software\Policies\Microsoft\Windows\Explorer" /v "HideRecommendedSection" /t REG_DWORD /d "1" /f  
# Disable Copilot
reg add "HKLM\zNTUSER\Software\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d "1" /f  
# Disable GameDVR
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f  
# Disable Cloud Content
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableCloudOptimizedContent" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableConsumerAccountStateContent" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f  
reg add "HKLM\zNTUSER\Software\Policies\Microsoft\Windows\CloudContent" /v "ConfigureWindowsSpotlight" /t REG_DWORD /d "2" /f  
reg add "HKLM\zNTUSER\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableSpotlightCollectionOnDesktop" /t REG_DWORD /d "1" /f  
reg add "HKLM\zNTUSER\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d "1" /f  
reg add "HKLM\zNTUSER\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f  
reg add "HKLM\zNTUSER\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f  
reg add "HKLM\zNTUSER\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnActionCenter" /t REG_DWORD /d "1" /f  
reg add "HKLM\zNTUSER\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnSettings" /t REG_DWORD /d "1" /f  
reg add "HKLM\zNTUSER\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightWindowsWelcomeExperience" /t REG_DWORD /d "1" /f  
reg add "HKLM\zNTUSER\Software\Policies\Microsoft\Windows\CloudContent" /v "IncludeEnterpriseSpotlight" /t REG_DWORD /d "0" /f  
# Disable Smartscreen
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\default\Browser\AllowSmartScreen" /v "value" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_SZ /d "Anywhere" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "Enabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV8" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "2301" /t REG_DWORD /d "3" /f  
# Restrict Internet Comm
reg add "HKLM\zSOFTWARE\Policies\Microsoft\InternetManagement" /v "RestrictCommunication" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoPublishingWizard" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d "2" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\EventViewer" /v "MicrosoftEventVwrDisableLinks" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" /v "NoRegistration" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f  
# Disable Error Reporting
reg add "HKLM\zSOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "AutoApproveOSDumps" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "IncludeKernelFaults" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "AllOrNone" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "IncludeMicrosoftApps" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "IncludeWindowsApps" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "IncludeShutdownErrs" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "ForceQueueMode" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d "0" /f  
reg delete "HKLM\zSOFTWARE\policies\microsoft\pchealth\errorreporting\dw" /v "dwfiletreeroot" /f  
reg delete "HKLM\zSOFTWARE\policies\microsoft\pchealth\errorreporting\dw" /v "dwreporteename" /f  
reg add "HKLM\zSOFTWARE\policies\microsoft\pchealth\errorreporting\dw" /v "DWAllowHeadless" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\policies\microsoft\pchealth\errorreporting\dw" /v "DWNoExternalURL" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\policies\microsoft\pchealth\errorreporting\dw" /v "DWNoFileCollection" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\policies\microsoft\pchealth\errorreporting\dw" /v "DWNoSecondLevelCollection" /t REG_DWORD /d "0" /f  
reg add "HKLM\zNTUSER\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "AutoApproveOSDumps" /t REG_DWORD /d "0" /f  
reg add "HKLM\zNTUSER\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f  
reg add "HKLM\zNTUSER\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f  
reg add "HKLM\zNTUSER\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f  
# Disable Experiments
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableExperimentation" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\Device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f  
# Disable Ads Info 
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\System" /v "EnableCdp" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "HttpAcceptLanguageOptOut" /t REG_SZ /d "reg add 'HKCU\Control Panel\International\User Profile' /v 'HttpAcceptLanguageOptOut' /t REG_DWORD /d '1' /f" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DisableEnterpriseAuthProxy" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DisableOneSettingsDownloads" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowCommercialDataPipeline" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDesktopAnalyticsProcessing" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitDiagnosticLogCollection" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitDumpCollection" /t REG_DWORD /d "1" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\default\System\AllowTelemetry" /v "value" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MicrosoftEdgeDataOptIn" /t REG_DWORD /d "0" /f  
# Disable Activity History
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f  
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f  

reg unload HKLM\zSOFTWARE  
reg unload HKLM\zSYSTEM  
reg unload HKLM\zNTUSER  

Write-Host
Write-Host "$([char]0x1b)[48;2;20;14;136m=== Adding License"
if ($Type -eq "24H2") {
    takeown /f "mount\Windows\System32\en-US\Licenses\_Default\EnterpriseG\placeholder.rtf"   
    icacls "mount\Windows\System32\en-US\Licenses\_Default\EnterpriseG\placeholder.rtf" /grant:r "$($env:USERNAME):(W)"  
    Copy-Item -Path "files\License\license.rtf" -Destination "mount\Windows\System32\en-US\Licenses\_Default\EnterpriseG\placeholder.rtf" -Force  
    Copy-Item -Path "files\License\license.rtf" -Destination "mount\Windows\System32\en-US\Licenses\_Default\EnterpriseG\license.rtf" -Force  
    Write-Host
}
else {
    $licensePath = "mount\Windows\System32\Licenses\neutral\_Default\EnterpriseG"; if (-not (Test-Path -Path $licensePath -PathType Container)) { New-Item -Path $licensePath -ItemType Directory -Force }
    Copy-Item -Path "files\License\license.rtf" -Destination "mount\Windows\System32\Licenses\neutral\_Default\EnterpriseG\license.rtf" -Force  
Write-Host
}

if ($ActivateWindows -eq "True") {
    Write-Host "$([char]0x1b)[48;2;20;14;136m=== Adding Activation Script for Windows"
    New-Item -ItemType Directory -Path "mount\Windows\Setup\Scripts" -Force  
    Copy-Item -Path "files\Scripts\SetupComplete.cmd" -Destination "mount\Windows\Setup\Scripts\SetupComplete.cmd" -Force
    Copy-Item -Path "files\Scripts\activate_kms38.cmd" -Destination "mount\Windows\Setup\Scripts\activate_kms38.cmd" -Force
    Write-Host
}

if ($RemoveEdge -eq "True") {
    if ($detectedBuild -ge 22621) {
    Write-Host "$([char]0x1b)[48;2;20;14;136m=== Removing Microsoft Edge"
    reg load HKLM\zSOFTWARE mount\Windows\System32\config\SOFTWARE  
    reg load HKLM\zSYSTEM mount\Windows\System32\config\SYSTEM  
    if (Test-Path 'mount\Program Files (x86)\Microsoft' -Type Container) { Remove-Item 'mount\Program Files (x86)\Microsoft' -Recurse -Force   }
    reg delete "HKLM\zSOFTWARE\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}" /f  
    reg delete "HKLM\zSOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdgeUpdate.exe" /f  
    reg delete "HKLM\zSOFTWARE\Wow6432Node\Microsoft\EdgeUpdate" /f  
    reg delete "HKLM\zSOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge" /f  
    reg delete "HKLM\zSOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update" /f  
    reg delete "HKLM\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView" /f  
    reg add "HKLM\zSOFTWARE\Policies\Microsoft\EdgeUpdate" /v CreateDesktopShortcutDefault /t REG_DWORD /d 0 /f  
    reg add "HKLM\zSOFTWARE\Policies\Microsoft\EdgeUpdate" /v RemoveDesktopShortcutDefault /t REG_DWORD /d 1 /f  
    reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "DisableEdgeDesktopShortcutCreation" /t REG_DWORD /d "1" /f  
    reg delete "HKLM\zSYSTEM\ControlSet001\Services\edgeupdate" /f  
    reg delete "HKLM\zSYSTEM\ControlSet001\Services\edgeupdatem" /f  
    reg unload HKLM\zSOFTWARE  
    reg unload HKLM\zSYSTEM  
    Write-Host
} else {
    Write-Host "$([char]0x1b)[48;2;20;14;136m=== Removing Microsoft Edge on Setup Complete"
    if (!(Test-Path "mount\Windows\Setup\Scripts" -Type Container)) {New-Item "mount\Windows\Setup\Scripts" -ItemType Directory -Force   }
    if (!(Test-Path "mount\Windows\Setup\Scripts\SetupComplete.cmd" -Type Leaf)) { Copy-Item "files\Scripts\SetupComplete.cmd" -Destination "mount\Windows\Setup\Scripts\SetupComplete.cmd" -Force   }
    Copy-Item -Path "files\Scripts\RemoveEdge.cmd" -Destination "mount\Windows\Setup\Scripts\RemoveEdge.cmd" -Force  
    Write-Host
}
}

Write-Host "$([char]0x1b)[48;2;20;14;136m=== Resetting Base"
Dism /Image:mount /Cleanup-Image /StartComponentCleanup /ResetBase  
Write-Host

Write-Host "$([char]0x1b)[48;2;20;14;136m=== Unmounting Install.wim"
dism /unmount-wim /mountdir:mount /commit  
Write-Host

Write-Host "$([char]0x1b)[48;2;20;14;136m=== Optimizing Install.wim"
& "files\wimlib-imagex" optimize install.wim  
Write-Host

Write-Host "$([char]0x1b)[48;2;20;14;136m=== Setting WIM Infos and Flags"
& "files\wimlib-imagex" info install.wim $ProIndex --image-property NAME="Windows $Windows Enterprise G" --image-property DESCRIPTION="Windows $Windows Enterprise G" --image-property FLAGS="EnterpriseG" --image-property DISPLAYNAME="Windows $Windows Enterprise G" --image-property DISPLAYDESCRIPTION="Windows $Windows Enterprise G"  
Write-Host

@("mount", "sxs") | ForEach-Object { if (Test-Path $_ -ErrorAction SilentlyContinue) { Remove-Item $_ -Recurse -Force -ErrorAction SilentlyContinue } }
$endTime = Get-Date
$elapsedTime = $endTime - $startTime

[System.Media.SystemSounds]::Asterisk.Play()
Write-Host
Write-Host "$([char]0x1b)[48;2;0;128;0m=== Reconstruction completed in $([math]::Floor($elapsedTime.TotalMinutes)) minutes and $($elapsedTime.Seconds) seconds ==="
Write-Host
pause
exit
