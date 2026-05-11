# Sec_AD

Automated tiered Active Directory hardening with security baseline GPOs, defense-in-depth controls, and best-effort rollback.

## Table of contents
- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [Module structure](#module-structure)
- [GPO linking strategy](#gpo-linking-strategy)
- [GPO catalog](gpo.md)
- [AD hardening (advanced, opt-in)](#ad-hardening)
- [Rollback (`restore.ps1`)](#restore)
- [Security considerations](#security-considerations)
- [Tests](#tests)
- [TODO](#todo)

<a id="overview"></a>
## 📦 Overview

`Sec_AD` deploys a tiered administration model in Active Directory (Tier 0 / Tier 1 / Tier 2 / Tier 1 Legacy), imports a curated set of security-hardening GPOs, links them granularly per sub-OU, and offers optional advanced hardening (tier ACL delegation, Authentication Policy Silos, privileged-group audit, sensitive-account flags) along with a best-effort rollback tool.

Designed to be:
- **Idempotent** — safe to re-run; existing objects and links are detected and skipped.
- **Auditable** — every run logs to a timestamped file and captures a JSON state baseline before any modification.
- **Reversible** — a separate `restore.ps1` reads the baseline and undoes what it can.

<a id="features"></a>
## ✨ Features

- Tiered OU structure (Tier0 / Tier1 / Tier2 / Tier1_Legacy + ADM containers)
- Security-hardening GPO import with forest-functional-level-aware selection
- Granular GPO linking per sub-OU (Workstations vs Servers vs Users vs Admins)
- Domain-level hardening: ADSI unauthenticated bind, machine account quota, krbtgt encryption types, AD Recycle Bin, LAPS, BitLocker prerequisites
- Optional AD hardening: tier OU ACL delegation, Authentication Policy Silos, Pre-Windows 2000 lockdown, Tier 0 sensitive flag, privileged group audit
- Centralized logging with severity levels
- Preflight validation (modules, privileges, connectivity, config integrity)
- AD state baseline capture for rollback
- `-WhatIf` / `-DryRun` everywhere
- Pester test suite (offline, no live AD required)

<a id="prerequisites"></a>
## ✅ Prerequisites

- Windows Server with RSAT (or run on a Domain Controller)
- PowerShell 5.1+ (PowerShell 7 supported via WindowsCompatibility for `GroupPolicy`)
- Modules: `ActiveDirectory`, `GroupPolicy`, `LAPS` (optional)
- Run as **Domain Administrator**
- AD forest/domain functional level ≥ 2008 R2 (Recycle Bin requires 2008 R2+)

<a id="usage"></a>
## ▶️ Usage

### Basic
```powershell
.\sec_ad.ps1
```

### Dry-run (recommended for first execution)
```powershell
.\sec_ad.ps1 -DryRun
```
Validates the environment, captures the baseline, and lists which functions would be invoked — without modifying AD.

### Verbose logging
```powershell
.\sec_ad.ps1 -LogLevel DEBUG
```

### `-WhatIf` semantics
All AD-modifying functions support `-WhatIf`:
```powershell
.\sec_ad.ps1 -WhatIf
```

### Skip safety nets (not recommended)
```powershell
.\sec_ad.ps1 -SkipPreflight
.\sec_ad.ps1 -SkipBackup
```

### Logs and backups
- Logs: `logs/sec_ad_YYYYMMDD_HHMMSS.log`
- State baselines: `backups/state_backup_YYYYMMDD_HHMMSS.json` (captured before any change)
- ACL backups: `backups/acl/acl_*.json` (when tier delegation runs)
- Pre-Win2000 backups: `backups/preWin2000_members_*.json`

### Configuration

Two config files in `Config/`:

`Global_config.json` — what to do:
```json
{
    "RootDN": "DC=lab,DC=local",
    "AdmName": "ADM",
    "TierNames": ["Tier0", "Tier1", "Tier2", "Tier1_Legacy"],
    "TargetDomain": "lab.local",
    "GPOBackupPath": "GPO",
    "Functions": {
        "InitializeADStructure": true,
        "ImportSecurityHardeningGPOs": true,
        "ApplyGPOsToTiers": true,
        "SetADSIUnauthenticatedBind": true,
        ...
        "SetTierOUDelegation": false,
        "NewTier0AuthenticationPolicySilo": false,
        "LockPreWindows2000Group": false,
        "GetPrivilegedGroupAudit": false,
        "SetTier0AccountSensitive": false
    }
}
```

`GPO_config.json` — which GPOs to link where (see [GPO linking strategy](#gpo-linking-strategy)).

<a id="module-structure"></a>
## 🧩 Module structure

- **Logging.psm1** — centralized logging (file + console, severity levels)
- **Validation.psm1** — preflight checks (modules with PS7 fallback, privileges, connectivity, config)
- **StateManagement.psm1** — AD state baseline capture + best-effort rollback (OUs, groups, GPO links, domain attributes, AccountNotDelegated flags, Authentication Policy Silos, privileged group membership)
- **GPO.psm1** — GPO import & granular tier/sub-OU linking
- **ADStructure.psm1** — tier OU structure deployment; `New-OU` and `New-Group` are private helpers (not exported)
- **ADHardening.psm1** — domain-level hardening (ADSI bind, machine account quota, Kerberos encryption types, Recycle Bin, LAPS, BitLocker), tier OU ACL delegation, Authentication Policy Silos, Pre-Win2000 lockdown, privileged-group audit, Tier 0 sensitive flag

<a id="gpo-linking-strategy"></a>
## 🔗 GPO linking strategy

GPOs are linked **per sub-OU**, not at the tier root. This avoids applying user-side GPOs to OUs that contain only computers and vice-versa.

### Configuration format

`GPO_config.json` `TierMappings` supports two formats:

**Granular** (recommended, used by default):
```json
"TierMappings": {
    "Tier2": {
        "description": "Workstations, end users",
        "subOUs": {
            "Workstations": { "gpos": [ "Bitlocker-Enabled", "..." ] },
            "Users":        { "gpos": [ "ScreenLock-enabled", "..." ] },
            "Admins":       { "gpos": [ "..." ] }
        }
    }
}
```

The special key `_root` links a GPO to the tier OU itself (`OU=_TierN,...`) so it inherits down to all sub-OUs.

**Legacy flat** (still supported):
```json
"TierMappings": {
    "Tier2": { "gpos": [ "Applocker-Enabled", "..." ] }
}
```

### Categorization reference

The shipped config classifies GPOs into four categories (visible in `_categories` of `GPO_config.json` as documentation):
- **AllComputers** — every machine OU (DCs, servers, workstations)
- **ServersOnly** — server-specific (LDAP server signing, server logs, RDP server controls)
- **WorkstationsOnly** — workstation-specific (BitLocker, AppLocker, Exploit Guard, LAPS)
- **UsersSide** — user-context settings (ScreenLock, WPAD-User, proxy lockdown)

`_categories` is documentation only; the script reads `TierMappings`.

### Idempotence

`Set-GPOsToTiers` reads existing links per OU once and skips any GPO already linked. Re-runs are safe. End-of-run summary shows: newly-linked, already-linked, skipped (GPO not in domain), skipped (OU missing), failed.

<a id="ad-hardening"></a>
## 🛡️ AD hardening (advanced, opt-in)

These functions are **disabled by default** in `Global_config.json`. Review each carefully before enabling. All support `-WhatIf` and capture JSON backups before changes.

| Function | What it does | Risk if misconfigured |
|---|---|---|
| `SetTierOUDelegation` | Creates `TierN_Admins` groups, grants FullControl on tier OU, denies cross-tier writes | Lockout if running admin is not in any tier admin group; mitigated by Domain Admins inherited rights |
| `NewTier0AuthenticationPolicySilo` | Creates/updates Auth Policy + Silo from `Config/Silo_config.json`; additive member assignment (never removes existing members) | Requires DFL ≥ 2012R2; start in `Audit` mode — `Enforce` blocks non-members from authenticating |
| `LockPreWindows2000Group` | Empties `S-1-5-32-554` membership after JSON backup | Legacy NT4 / pre-W2K systems may break |
| `GetPrivilegedGroupAudit` | Read-only audit of DA/EA/Schema Admins; writes JSON report to `logs/` | None (read-only) |
| `SetTier0AccountSensitive` | Marks all users under `_Tier0\Admins` as `AccountNotDelegated=$true` | Breaks Kerberos delegation for those accounts (intentional) |

### Authentication Policy Silo (`Config/Silo_config.json`)

All silo parameters live in a single JSON file — there is no `-Mode`, `-PolicyName`, or `-SiloName` parameter on the function:

```json
{
    "PolicyName": "Tier0-AuthPolicy",
    "SiloName":   "Tier0-Silo",
    "Mode":       "Audit",
    "TGTLifetimeMinutes": 45,
    "Members": {
        "Users":     ["t0-admin1", "t0-admin2"],
        "Computers": ["DC01$", "DC02$", "PAW-T0-01$"],
        "Services":  []
    }
}
```

**Mode semantics:**
- `Audit` — policy and silo are created but not enforced; TGT issuance is not restricted. Monitor DC events 105/305, 4625, 4768–4770.
- `Enforce` — non-members are blocked from authenticating to silo-protected resources. Switch only after validating the audit log.

**Re-running is safe:** existing policy/silo objects are updated (Mode + SDDL conditions), not recreated. Member assignment is **additive** — accounts in the config not yet assigned to the silo are added; accounts already assigned but absent from the config are never removed.

**To remove a member manually:**
```powershell
Set-ADAccountAuthenticationPolicySilo -Identity <SamAccountName> -AuthenticationPolicySilo $null
```

**DC prerequisite (GPO):** "KDC support for claims, compound authentication and Kerberos armoring" → `Always provide claims` on all Domain Controllers.

### Manual cleanup helper

`Remove-PrivilegedGroupMember` is **not** wired to the orchestrator on purpose. Use it manually after reviewing the audit:

```powershell
Import-Module .\Modules\ADHardening.psm1

# Audit first
Get-PrivilegedGroupAudit -ReportPath .\logs\audit.json

# Dry-run a removal
Remove-PrivilegedGroupMember -GroupName 'Domain Admins' -MemberSamAccountName 'jdoe' -WhatIf

# Real removal (will prompt due to ConfirmImpact=High)
Remove-PrivilegedGroupMember -GroupName 'Domain Admins' -MemberSamAccountName 'jdoe'
```

The built-in `Administrator` is refused unless you pass `-AllowAdministratorRemoval`.

### Recommended order

1. `InitializeADStructure` — create the OU/group skeleton
2. `ImportSecurityHardeningGPOs` + `ApplyGPOsToTiers`
3. `SetTier0AccountSensitive` — quick win, low risk
4. `LockPreWindows2000Group` — verify no legacy dependencies first
5. `GetPrivilegedGroupAudit` — review report, plan removals
6. `SetTierOUDelegation` — populate `TierN_Admins` groups before enabling
7. `NewTier0AuthenticationPolicySilo` — last; reads `Config/Silo_config.json`; declare members there; start with `Mode: Audit`, switch to `Enforce` after validation

<a id="restore"></a>
## ↩️ Rollback (`restore.ps1`)

Sec_AD captures backup artifacts on every run:
- `backups/state_backup_*.json` — snapshot before any change (OUs, groups, GPO links, domain attributes, Tier 0 sensitive flags, Authentication Policy Silos, privileged group membership)
- `backups/acl/acl_*.json` — OU ACL snapshots before delegation changes
- `backups/preWin2000_members_*.json` — group membership before lockdown

The `restore.ps1` companion script reverses these. It is intentionally a **separate entry point** from `sec_ad.ps1` to avoid mixing apply and rollback flows.

### List available backups
```powershell
.\restore.ps1 -List
```

### Preview a state restore
```powershell
.\restore.ps1 -StateBackupFile .\backups\state_backup_20260510_213601.json -All -WhatIf
```

The diff is printed: domain attributes to revert, GPO links to add/remove, groups and OUs to delete (only those created since the backup, only if empty), sensitive flags to revert, silos to delete, privileged group members to remove/re-add.

### Granular control

```powershell
# Only restore domain attributes
.\restore.ps1 -StateBackupFile <path> -IncludeDomainAttrs

# Only restore GPO links (e.g. after a botched re-link)
.\restore.ps1 -StateBackupFile <path> -IncludeGPOLinks

# Revert AccountNotDelegated on Tier 0 admins
.\restore.ps1 -StateBackupFile <path> -IncludeAccountDelegation

# Delete silos absent from baseline + revert silo membership
.\restore.ps1 -StateBackupFile <path> -IncludeSilos

# Revert Domain Admins / EA / Schema Admins membership
.\restore.ps1 -StateBackupFile <path> -IncludePrivilegedGroups

# Everything
.\restore.ps1 -StateBackupFile <path> -All
```

### Restore an OU's ACL
```powershell
.\restore.ps1 -ACLBackupFile .\backups\acl\acl_OU_Tier0_DC_lab_DC_local_20260510_215000.json
```

### Re-add Pre-Win2000 members
```powershell
.\restore.ps1 -PreWin2000BackupFile .\backups\preWin2000_members_20260510_220000.json
```

### Backward compatibility

State backup files written before the `AccountNotDelegated`, `AuthNPolicySilos`, and `PrivilegedGroups` fields were added are handled transparently: `Compare-StateBackup` and `Restore-StateBackup` null-check each section and silently skip absent ones.

### What is NOT reversible

- **AD Recycle Bin enable** — irreversible by design (Microsoft).
- **LAPS schema update** — schema attributes cannot be removed.
- **GPO content imports** — restore unlinks but does not delete the GPO objects themselves. Use `Remove-GPO` manually.
- **OUs with user-created child objects** — restore refuses to delete; move children out first.

<a id="security-considerations"></a>
## 🔐 Security considerations

- Requires **Domain Administrator** rights
- Review every GPO before applying
- Always test in a lab before production
- Maintain separate full system-state backups of every DC; the JSON baselines complement but do not replace them

<a id="tests"></a>
## 🧪 Tests

Offline Pester tests (no live AD required):

```powershell
.\Tests\Invoke-Tests.ps1

# With CI-friendly NUnit XML output
.\Tests\Invoke-Tests.ps1 -CI
```

The runner auto-installs Pester 5+ if needed. Output: `Tests/TestResults.xml` (CI mode).

<a id="todo"></a>
## 📝 TODO

- [x] Centralized logging with file output
- [x] Preflight validation checks (with PS7 fallback for GroupPolicy)
- [x] `-WhatIf` / `-DryRun` support across all modification functions
- [x] AD state baseline capture for rollback
- [x] Extended baseline: `AccountNotDelegated`, Authentication Policy Silos, privileged group membership
- [x] Pester test suite (offline)
- [x] OU/group ACL delegation per tier
- [x] Authentication Policy Silos for Tier 0
- [x] Audit privileged groups (DA / EA / Schema Admins)
- [x] Pre-Windows 2000 group lockdown
- [x] Tier 0 account sensitive flag
- [x] Granular GPO linking (per sub-OU instead of tier root)
- [x] Restore from state baseline (best-effort rollback, including hardening axes)
- [x] Module restructuring: 9 → 6 modules (Common→ADStructure, ADSecurity+ADHardening, Backup+Restore→StateManagement)
- [ ] CI pipeline (GitHub Actions: PSScriptAnalyzer + Pester)
- [ ] Extend compatibility with hybrid environments