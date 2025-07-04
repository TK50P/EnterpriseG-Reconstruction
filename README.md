<div align="center">

## Note
This project is a revival of xLSX285's original work. All original repositories have been forked or migrated to this repo for continued maintenance and usage.

## [Download Latest Version](https://github.com/xLSX285/EnterpriseG/archive/refs/heads/main.zip)
</div>
<div align="center">
  <img src="https://github.com/user-attachments/assets/1c8522f7-c557-4171-8827-111af27b9a38" alt="Image Description">

</div>

<div align="center">
  
# How to reconstruct Enterprise G
</div>

`All you need to provide is:`
- Windows 10/11 Pro en-US install.wim image **without** updates (XXXXX.1)

> [**UUP Dump**](https://uupdump.net/) can create a Windows Pro ISO in en-US **without** updates (untick the **Include updates (Windows converter only)** box).
> 
**Hot tip:** If you build a fresh ISO using UUP Dump, set `AppsLevel` to **1** inside `ConvertConfig.ini`, this will only install Windows Security and the Microsoft Store as apps preinstalled! Additionally, on 26100 and later, setting `SkipEdge` to **1** wont preinstall Microsoft Edge or Webview.
> 
Supported Builds: 
- [17763](https://uupdump.net/download.php?id=6ce50996-86a2-48fd-9080-4169135a1f51&pack=en-us&edition=professional) (1809), [18363](https://uupdump.net/download.php?id=d371aab7-52f8-45f3-b2a4-a417d8e54cb5&pack=en-us&edition=professional) (1903), [19041](https://uupdump.net/download.php?id=a80f7cab-84ed-43f4-bc6b-3e1c3a110028&pack=en-us&edition=professional) (2004), [22000](https://uupdump.net/download.php?id=6cc7ea68-b7fb-4de1-bf9b-1f43c6218f6f&pack=en-us&edition=professional) (21H2), [22621](https://uupdump.net/download.php?id=356c1621-04e7-4e66-8928-03a687c3db73&pack=en-us&edition=professional) (22H2) & [26100](https://uupdump.net/download.php?id=3d68645c-e4c6-4d51-8858-6421e46cb0bb&pack=en-us&edition=professional) (24H2)


`How to get started:`
1. Place install.wim in the directory of the script
2. Adjust config.json if necessary
3. Run **Build.ps1** in PowerShell as Administrator

> Run this command in Powershell if Build.ps1 is not starting. `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
> 
Once the reconstruction process is complete, you will find the new `install.wim` file in the same folder where you placed the original install.wim file. (**Please note:** your original `install.wim` file has been overwritten and **cannot be restored!**)
To proceed, you can create a new ISO using AnyBurn or any similar software. If you have already created a bootable Windows installation USB drive, simply copy the new `install.wim` file and replace the existing one located in the `sources` directory of your USB drive.
>
<div align="center">
  
# Config.json

</div>

## ActivateWindows

- `True`: Activate Windows via KMS38 `Default`
- `False`: Windows wont be activated

## RemoveEdge

- `True`: Bring your own web browser `Default`
- `False`: Microsoft Edge remains installed

<div align="center">
  
# Known "issues" with Enterprise G reconstruction
</div>

- No ARM64 support. x86 can be reconstructed with editing scripts and mum files. However this project only covers X86_64/AMD64 (64 Bit PCs support only) yet.
- No Reconstructions possible under 17763 (1809). while 1703 initiately introduced EnterpriseG Editionspectific ESD, but can't be reconstructed.
<div align="center">

# Please note that...
I'm not actively maintaining this project. I'll push some commits here and there to ensure support for future Windows builds and some optimizations, that's it. This project requires some knowledge. Please don't ask me for help.

This script WILL NOT automatically fully debloat your Windows system. Instead, it will overwrite the Pro Edition in your install.wim with the Enterprise G Edition of Windows, resulting in the disabling of Windows Defender antivirus, reduced telemetry, and other adjustments (Handled by EnterpriseG SKU product policies).

Please note that the actual EnterpriseG version used by government entities, maintained by CMGE and others, includes additional features and modifications that are not publicly available and are not covered by simply running this script or product policies of this SKU.
</div>
