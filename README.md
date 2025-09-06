# Active Directory Tiered Administration Structure

This PowerShell project automates a secure, tiered administration model for Active Directory (Tier 0/1/2), including OU layout, groups/permissions, and a curated set of hardening GPOs aligned with best practices.

## Table of contents

- Quickstart
- Features
- Prerequisites
- Installation
- Configuration (with examples)
- GPO Documentation (catalog and verification)
- Usage
- Module Structure
- Security Considerations
- Error Handling

## Quickstart

1. Update `Config\Global_config.json` for your environment (see Configuration).
2. Ensure GPO backups exist in `GPO/` (GUID folders with `gpreport.xml`).
3. Open PowerShell as Administrator and run:
   ```powershell
   .\build_Tiers.ps1
   ```
4. Review imported GPOs and link them to the appropriate OUs.

## Features

- **Tiered Administrative Structure**
  - Creates separate administrative tiers (Tier 0, Tier 1, Tier 2, Tier1_Legacy)
  - Implements dedicated OUs for each tier
  - Sets up appropriate security groups and permissions
  - Create Local Groups for Administration LAPS-Pwd-Read

- **GPO Management**
  - Imports Group Policy Objects (GPOs) based on the forest functional level (2016/2025)
  - Configures security settings for each tier
  - [!] Warning: After import, add `DOMAIN\LAPS-Pwd-Read` to LAPS “Configure authorized password decryptors”

- **Security Hardening**
  - Configures ADSI unauthenticated bind settings
  - Implements proper security group structure
  - Sets Machine Account Quota to secure value
  - Enables Active Directory Recycle Bin
  - Configures Local Administrator Password Solution (LAPS)
  - Creates dedicated LAPS password reader groups

## Prerequisites

- Windows Server with Active Directory Domain Services
- PowerShell 5.1 or higher
- Active Directory PowerShell module
- Group Policy PowerShell module
- Domain Administrator privileges

## Prerequisites

- Windows Server with Active Directory Domain Services
- PowerShell 5.1 or higher
- Active Directory and Group Policy PowerShell modules
- Domain Administrator privileges

## Installation

1. Clone or download this repository
2. Ensure all required PowerShell modules are installed
3. Modify the `Config\Global_config.json` file according to your environment

## Configuration

The `Config\Global_config.json` file contains all the configuration settings:

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
        "InitializeADStructure": true,
        ...
    }
}
```

The `Config\GPO_config.json` file lists which GPOs are imported for each functional level:

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
                "Kerberos-Armoring-Enabled",
                "LAPS-Enabled",
                "LDAP-CBT-Enabled",
                ...
            ]
        },
        "Level2016": {
            "description": "GPOs for Windows 2016 and below",
            "gpos": [
                "LMHASH-Disabled"
            ]
        },
        "Level2025": {
            "description": "GPOs for Windows 2025 and above",
            "gpos": [
                "SMB-NTLM-Disabled"
            ]
        }
    }
}
```

### Configuration Options

- `RootDN`: The root DN of your Active Directory domain
- `AdmName`: Name for the administrative structure
- `TierNames`: Array of tier names to create
- `SubOUs`: Standard OUs to create in Tier 2
- `Tier0and1SubOUs`: Additional OUs for Tier 0 and Tier 1
- `DisabledOU`: Name for the disabled accounts OU
- `GPOBackupPath`: Path to GPO backup files
- `TargetDomain`: Target domain name
- `Functions`: Toggle individual functions on/off

## GPO Documentation

For a detailed catalog of all provided GPOs, verified settings from backups, and recommended linking, see: [`gpo.md`](gpo.md).

Highlights:
- Mapping by level (Common, 2016, 2025)
- Verified parameters pulled from `gpreport.xml`
- Recommended linking by tier (Tier 0/1/2)

## Tier Customization

The GPO configuration now supports flexible tier-based mappings through the `Config\GPO_config.json` file. This allows you to customize which GPOs are applied to each administrative tier.

### Configuration Structure

The `TierMappings` section in `GPO_config.json` defines GPO assignments for each tier:

```json
{
    "TierMappings": {
        "Tier0": {
            "description": "GPOs for Tier 0 (Domain Controllers, PAW)",
            "gpos": [
                "Applocker-Enabled",
                "Bitlocker-Enabled",
                "Bloodhound-Mitigation",
                // ... other GPOs
            ]
        },
        "Tier1": {
            "description": "GPOs for Tier 1 (Administrative Servers)",
            "gpos": [
                "Applocker-Enabled",
                "Bitlocker-Enabled",
                // ... other GPOs
            ]
        },
        "Tier2": {
            "description": "GPOs for Tier 2 (Workstations, Users)",
            "gpos": [
                "Applocker-Enabled",
                "Bitlocker-Enabled",
                "Logs-Advanced-Workstation-Enabled",
                // ... other GPOs
            ]
        },
        "Tier1_Legacy": {
            "description": "GPOs for Tier 1 Legacy (Legacy Administrative Servers)",
            "gpos": [
                "Applocker-Enabled",
                "Bitlocker-Enabled",
                // ... other GPOs
            ]
        }
    }
}
```

### Usage Modes

- **With AD Structure** (`InitializeADStructure = true`): 
  - Creates the AD structure
  - Applies GPOs according to the `TierMappings` configuration
- **Import Only** (`InitializeADStructure = false`): 
  - Imports GPOs according to the `GPOs` configuration (Common, Level2016, Level2025)

### Customization Example

To add a new GPO specific to Tier 0:

```json
"Tier0": {
    "description": "GPOs for Tier 0 (Domain Controllers, PAW)",
    "gpos": [
        "Applocker-Enabled",
        "Bitlocker-Enabled",
        "New-Security-GPO",  // <- New GPO added
        // ... other GPOs
    ]
}
```

## Usage

1. Open PowerShell as Administrator
2. Navigate to the project directory
3. Run the main script:
```powershell
.\build_Tiers.ps1
```

## Module Structure

- `Common.psm1`: Common functions for OU and group creation
- `GPO.psm1`: GPO import and management functions
- `ADSecurity.psm1`: AD Security functions
- `ADStructure.psm1`: Main AD structure creation functions

## Security Considerations

- The script requires Domain Administrator privileges
- Review the GPO settings before importing
- Ensure proper backup before running in production
- Test in a lab environment first

## Error Handling

The script includes comprehensive error handling:
- Validates configuration before execution
- Checks for required modules and functions
- Provides detailed error messages
- Graceful failure handling


## TODO

