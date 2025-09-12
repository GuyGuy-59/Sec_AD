# Active Directory Tiered Administration Structure

This PowerShell project automates the deployment of a secure, tiered administration model for Active Directory (Tier 0/1/2), including OU layout, groups/permissions, and curated hardening GPOs aligned with industry best practices.

---

## 📑 Table of Contents
- [Quickstart](#quickstart)  
- [Features](#features)  
- [Prerequisites](#prerequisites)  
- [Installation](#installation)  
- [Configuration](#configuration)  
  - [Configuration Options](#configuration-options)  
- [GPO Documentation](#gpo-documentation)  
- [Tier Customization](#tier-customization)  
  - [Usage Modes](#usage-modes)  
  - [Customization Example](#customization-example)  
- [Usage](#usage)  
- [Module Structure](#module-structure)  
- [Security Considerations](#security-considerations)  
- [Error Handling](#error-handling)  
- [TODO](#todo)  

---

## 🚀 Quickstart

1. Update `Config\Global_config.json` for your environment (see [Configuration](#configuration)).  
2. Ensure GPO backups exist in `GPO/` (GUID folders with `gpreport.xml`).  
3. Open PowerShell as Administrator and run:  

   ```powershell
   .\build_Tiers.ps1
   ```

4. Review imported GPOs and link them to the appropriate OUs.  

---

## ✨ Features

### Tiered Administrative Structure
- Creates dedicated tiers: **Tier 0, Tier 1, Tier 2, Tier1_Legacy**  
- Deploys OUs per tier  
- Configures security groups and permissions  
- Creates local admin groups for LAPS password readers  

### GPO Management
- Imports GPOs based on forest functional level (2016/2025)  
- Configures tier-specific security settings  
- ⚠️ **Important:** After import, add `DOMAIN\LAPS-Pwd-Read` to LAPS *“Configure authorized password decryptors”*  

### Security Hardening
- Configures ADSI unauthenticated bind  
- Implements hardened security group structure  
- Sets Machine Account Quota to a secure value  
- Enables AD Recycle Bin  
- Configures Local Administrator Password Solution (LAPS)  
- Creates dedicated password reader groups  

---

## 📋 Prerequisites
- Windows Server with Active Directory Domain Services  
- PowerShell **5.1+**  
- Active Directory PowerShell module  
- Group Policy PowerShell module  
- Domain Administrator privileges  

---

## ⚙️ Installation
1. Clone or download this repository.  
2. Ensure all required PowerShell modules are installed.  
3. Adjust `Config\Global_config.json` for your environment.  

---

## 🛠️ Configuration

### Global Settings (`Global_config.json`)
```json
{
    "RootDN": "DC=serval,DC=int",
    "AdmName": "ADM",
    "TierNames": ["Tier0", "Tier1", "Tier2", "Tier1_Legacy"],
    "SubOUs": ["Admins", "Groups", "Services"],
    "Tier0and1SubOUs": ["Admins", "Groups", "Servers", "Services"],
    "DisabledOU": "Disabled",
    "GPOBackupPath": "gpo",
    "TargetDomain": "serval.int",
    "Functions": {
        "InitializeADStructure": true
    }
}
```

### GPO Selection (`GPO_config.json`)
```json
{
    "GPOs": {
        "Common": {
            "description": "Common GPOs for all functional levels",
            "gpos": [
                "Applocker-enabled",
                "Bloodhound-Mitigation",
                "IPv6-Disabled",
                "Kerberos-AES-Enabled",
                ...
            ]
        },
        "Level2016": {
            "description": "GPOs for Windows 2016 and below",
            "gpos": ["LMHASH-Disabled"]
        },
        "Level2025": {
            "description": "GPOs for Windows 2025 and above",
            "gpos": ["SMB-NTLM-Disabled"]
        }
    }
}
```

### Configuration Options
- **RootDN**: Root DN of your AD domain  
- **AdmName**: Administrative structure prefix  
- **TierNames**: Tiers to deploy  
- **SubOUs**: Standard OUs for Tier 2  
- **Tier0and1SubOUs**: Extended OUs for Tier 0 & 1  
- **DisabledOU**: OU name for disabled accounts  
- **GPOBackupPath**: Path to GPO backups  
- **TargetDomain**: Domain FQDN  
- **Functions**: Enable/disable individual functions  

---

## 📚 GPO Documentation
See [`gpo.md`](gpo.md) for:  
- Full catalog of available GPOs  
- Verified settings extracted from `gpreport.xml`  
- Recommended linking per tier  

---

## 🎯 Tier Customization

### TierMappings Example
```json
{
    "TierMappings": {
        "Tier0": {
            "description": "Domain Controllers, PAW",
            "gpos": ["Applocker-Enabled", "Bitlocker-Enabled", "Bloodhound-Mitigation"]
        },
        "Tier1": {
            "description": "Administrative Servers",
            "gpos": ["Applocker-Enabled", "Bitlocker-Enabled"]
        },
        "Tier2": {
            "description": "Workstations, Users",
            "gpos": ["Applocker-Enabled", "Bitlocker-Enabled", "Logs-Advanced-Workstation-Enabled"]
        }
    }
}
```

### Usage Modes
- **Full AD Deployment** (`InitializeADStructure = true`)  
  → Creates AD structure **and** applies tier mappings.  
- **GPO Import Only** (`InitializeADStructure = false`)  
  → Imports only the configured GPO sets (Common/2016/2025).  

### Adding a Custom GPO
```json
"Tier0": {
    "description": "Domain Controllers, PAW",
    "gpos": [
        "Applocker-Enabled",
        "Bitlocker-Enabled",
        "New-Security-GPO"  // custom GPO
    ]
}
```

---

## ▶️ Usage
```powershell
.\build_Tiers.ps1
```

---

## 🧩 Module Structure
- **Common.psm1** → OU & group creation helpers  
- **GPO.psm1** → GPO import & management  
- **ADSecurity.psm1** → Security-related functions  
- **ADStructure.psm1** → AD structure deployment  

---

## 🔐 Security Considerations
- Requires **Domain Administrator** rights  
- Review GPOs before applying  
- Always test in a lab before production  
- Ensure full AD backups are available  

---

## ⚠️ Error Handling
- Validates config files before execution  
- Checks for required modules/functions  
- Provides descriptive error messages  
- Graceful exit on failure  

---

## 📝 TODO
- Add advanced reporting for applied GPOs  
- Improve rollback/restore support  
- Extend compatibility with hybrid environments  
