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
   .\sec_ad.ps1
   ```

4. Review imported GPOs and link them to the appropriate OUs.  

---

## 🏗️ Architecture

This project implements a **Tiered Administration Model** for Active Directory, following Microsoft's security best practices:

```
┌─────────────────────────────────────────────────────────────┐
│                    Domain Root (DC=serval,DC=int)          │
├─────────────────────────────────────────────────────────────┤
│  ┌─ _ADM (Administrative Structure)                        │
│  │  ├─ Tier0 (Domain Controllers, PAW)                    │
│  │  ├─ Tier1 (Administrative Servers)                     │
│  │  ├─ Tier2 (Workstations, Users)                        │
│  │  └─ Tier1_Legacy (Legacy Systems)                      │
├─────────────────────────────────────────────────────────────┤
│  ┌─ _Tier0 (Production Tiers)                              │
│  │  ├─ PAW/Disabled                                        │
│  │  └─ Groups/Admins/Servers/Services/Disabled             │
│  ├─ _Tier1                                                 │
│  │  └─ Groups/Admins/Servers/Services/Disabled             │
│  ├─ _Tier2                                                 │
│  │  ├─ Users/Workstations/Disabled                         │
│  │  └─ Admins/Groups/Services/Disabled                     │
│  └─ _Tier1_Legacy                                          │
│      └─ Groups/Admins/Servers/Services/Disabled             │
└─────────────────────────────────────────────────────────────┘
```

### Security Model
- **Tier 0**: Domain Controllers, PAW (Privileged Access Workstations)
- **Tier 1**: Administrative servers, management tools
- **Tier 2**: End-user workstations and regular servers
- **Tier1_Legacy**: Legacy administrative systems requiring compatibility

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
  - Creates AD structure **and** applies tier mappings
  - **Imports GPOs** according to the `GPOs` configuration (Common, Level2016, Level2025)
  - **Applies GPOs** according to the `TierMappings` configuration to specific tier OUs
- **GPO Import Only** (`InitializeADStructure = false`)  
  - Imports GPOs according to the `GPOs` configuration (Common, Level2016, Level2025)
  - **Note**: GPOs are imported globally and must be manually linked to OUs

### Execution Order

When `InitializeADStructure = true`, the script executes in this order:

```
┌─────────────────────────────────────────────────────────────┐
│                    Script Execution Flow                    │
├─────────────────────────────────────────────────────────────┤
│  1. InitializeADStructure                                   │
│     ├─ Create _ADM structure                               │
│     ├─ Create _Tier0, _Tier1, _Tier2, _Tier1_Legacy OUs   │
│     ├─ Create sub-OUs (Admins, Groups, Services, etc.)     │
│     └─ Create security groups (Tier_Users, LAPS-Pwd-Read)  │
├─────────────────────────────────────────────────────────────┤
│  2. ImportSecurityHardeningGPOs                            │
│     ├─ Read GPO_config.json                                │
│     ├─ Determine functional level (2016/2025)              │
│     ├─ Select GPOs to import (Common + Level-specific)     │
│     └─ Import GPOs from backup files to domain             │
├─────────────────────────────────────────────────────────────┤
│  3. ApplyGPOsToTiers                                       │
│     ├─ Read TierMappings from GPO_config.json             │
│     ├─ For each tier:                                      │
│     │   ├─ Verify tier OU exists                           │
│     │   ├─ Get GPOs for this tier                          │
│     │   └─ Link GPOs to tier OU                            │
│     └─ Report success/failures                             │
└─────────────────────────────────────────────────────────────┘
```

**Key Points:**
- GPOs are **always imported** before being applied to tiers
- Each tier gets its specific GPOs based on `TierMappings`
- The script validates OUs exist before linking GPOs

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

### Basic Usage
```powershell
# Run as Domain Administrator
.\sec_ad.ps1
```

### Advanced Usage
```powershell
# Check configuration first
Get-Content .\Config\Global_config.json | ConvertFrom-Json

# Run with verbose output
.\sec_ad.ps1 -Verbose

# Check GPO status after execution
Get-GPO -All | Where-Object {$_.DisplayName -like "*Security*"}
```

### Post-Execution Steps
1. **Verify GPO Links**: Check that GPOs are properly linked to tier OUs
2. **Configure LAPS**: Add `DOMAIN\LAPS-Pwd-Read` to LAPS decryptors
3. **Test Policies**: Verify GPOs are applying correctly
4. **Review Logs**: Check PowerShell execution logs for any warnings

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

## 🚨 Troubleshooting

### Common Issues

**GPOs not found during tier application:**
- Ensure GPOs are imported first (`ImportSecurityHardeningGPOs = true`)
- Check that GPO backup files exist in the specified path
- Verify GPO names match exactly in `GPO_config.json`

**OU not found errors:**
- Ensure `InitializeADStructure = true` is set
- Check that `RootDN` is correct for your domain
- Verify tier names match between `Global_config.json` and `GPO_config.json`

**Permission errors:**
- Run PowerShell as Domain Administrator
- Ensure you have GPO creation and linking permissions
- Check that the target domain is accessible

### Debug Mode
```powershell
# Enable detailed logging
$VerbosePreference = "Continue"
.\sec_ad.ps1
```

## 📝 TODO
- [ ] Add advanced reporting for applied GPOs  
- [ ] Improve rollback/restore support  
- [ ] Extend compatibility with hybrid environments
- [ ] Add GPO validation before import
- [ ] Create automated testing framework  
