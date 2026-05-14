<#
.SYNOPSIS
    State capture, diff, and restore helpers for Sec_AD.

.DESCRIPTION
    Two-phase state management for rollback after Sec_AD changes:

    State capture (New-StateBackup) saves to JSON:
      - Domain-level attributes  : ms-DS-MachineAccountQuota, msDS-Other-Settings
      - OU existence             : tier OUs (existed/absent before the run)
      - Managed groups           : LAPS-Pwd-Read, PAW-Tier0, PAW-Tier1
      - GPO links                : per-tier OU link list
      - AccountNotDelegated      : flag on accounts in the Tier0 Admins OU
      - Authentication Policy Silos : existing msDS-AuthNPolicySilo objects
      - Privileged group membership : DA, EA, SA, Administrators, Operators

    Restore (Restore-StateBackup) is best-effort; AD operations are not transactional.
    Each category is controlled by an -Include* switch (or -All).
    What it will NOT do:
      - Delete OUs with user-created child objects
      - Re-create deleted OUs (backup records existence only, not content)
      - Reverse irreversible operations (Recycle Bin, LAPS schema, GPO imports)
      - Delete linked Authentication Policies (only the silo container is removed)

    Functions exported:
      - New-StateBackup               : capture AD state baseline to JSON
      - Get-LatestStateBackup         : find the most recent backup file
      - Show-StateBackup              : display a backup summary to the log
      - Compare-StateBackup           : diff a backup against current AD state (read-only)
      - Restore-StateBackup           : apply baseline diff to AD (best-effort)
      - Restore-OUSecurityDescriptor  : restore an OU ACL from a backup file
      - Restore-PreWindows2000Members : re-add Pre-Win2000 group members from backup
      - Get-AvailableBackups          : list backup files in standard directories
#>

# =============================================================================
# New-StateBackup
# =============================================================================

function New-StateBackup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$BackupDirectory,
        [Parameter(Mandatory)] [string]$RootDN,
        [Parameter(Mandatory)] [string]$TargetDomain,
        [Parameter()]          [string[]]$TierNames = @('Tier0', 'Tier1', 'Tier2', 'Tier1_Legacy'),
        [Parameter()]          [string]$AdmName     = 'ADM'
    )

    if (-not (Test-Path $BackupDirectory)) {
        New-Item -ItemType Directory -Path $BackupDirectory -Force -WhatIf:$false -Confirm:$false | Out-Null
    }

    $timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupFile = Join-Path $BackupDirectory "state_backup_${timestamp}.json"

    Write-Log "`n=== Capturing AD state baseline ===" -Level INFO -Color Cyan
    Write-Log "Backup file: $backupFile" -Level INFO

    $state = [ordered]@{
        Timestamp           = (Get-Date -Format 'o')
        TargetDomain        = $TargetDomain
        RootDN              = $RootDN
        TierNames           = $TierNames
        AdmName             = $AdmName
        DomainObject        = $null
        OUs                 = @()
        Groups              = @()
        GPOLinks            = @()
        AccountNotDelegated = @()
        AuthNPolicySilos    = @()
        PrivilegedGroups    = @()
    }

    # ---- Domain-level attributes ----
    try {
        $domainObj = Get-ADObject -Identity $RootDN -Properties 'ms-DS-MachineAccountQuota', 'msDS-Other-Settings' -ErrorAction Stop
        $state.DomainObject = @{
            DistinguishedName           = $domainObj.DistinguishedName
            'ms-DS-MachineAccountQuota' = $domainObj.'ms-DS-MachineAccountQuota'
            'msDS-Other-Settings'       = @($domainObj.'msDS-Other-Settings')
        }
        Write-Log "  [OK] Captured domain attributes" -Level SUCCESS
    } catch {
        Write-Log "  [!] Could not capture domain attributes: $($_.Exception.Message)" -Level WARN
    }

    # ---- OU existence snapshot ----
    foreach ($tier in $TierNames) {
        $tierOU = "OU=_$tier,$RootDN"
        try {
            $ou = Get-ADOrganizationalUnit -Identity $tierOU -ErrorAction Stop
            $state.OUs += @{ DN = $ou.DistinguishedName; Name = $ou.Name; ExistedBefore = $true }
        } catch {
            $state.OUs += @{ DN = $tierOU; Name = "_$tier"; ExistedBefore = $false }
        }
    }

    # ---- Managed groups ----
    $managedGroups = @(
        @{ Name = 'LAPS-Pwd-Read-T2'; Path = "OU=Tier2,OU=_$AdmName,$RootDN" }
        @{ Name = 'LAPS-Pwd-Read-T0'; Path = "OU=Tier0,OU=_$AdmName,$RootDN" }
        @{ Name = 'PAW-Tier0';     Path = "OU=Tier0,OU=_$AdmName,$RootDN" }
        @{ Name = 'PAW-Tier1';     Path = "OU=Tier1,OU=_$AdmName,$RootDN" }
    )
    foreach ($g in $managedGroups) {
        try {
            $existing = Get-ADGroup -Filter "Name -eq '$($g.Name)'" -ErrorAction SilentlyContinue
            $state.Groups += @{
                Name          = $g.Name
                Path          = $g.Path
                ExistedBefore = ($null -ne $existing)
                DN            = if ($existing) { $existing.DistinguishedName } else { $null }
            }
        } catch {
            Write-Log "  [!] Group capture issue ($($g.Name)): $($_.Exception.Message)" -Level WARN
        }
    }

    # ---- GPO links on tier OUs ----
    foreach ($tier in $TierNames) {
        $tierOU = "OU=_$tier,$RootDN"
        try {
            $links = (Get-GPInheritance -Target $tierOU -Domain $TargetDomain -ErrorAction Stop).GpoLinks
            $state.GPOLinks += @{
                Target = $tierOU
                Links  = $links | ForEach-Object {
                    @{ DisplayName = $_.DisplayName; Enabled = $_.Enabled; Order = $_.Order }
                }
            }
        } catch {
            # OU may not exist yet on first run — that's fine
        }
    }

    # ---- AccountNotDelegated on Tier0 admin accounts ----
    try {
        $tier0AdminsOU = "OU=Admins,OU=Tier0,OU=_$AdmName,$RootDN"
        $accounts = Get-ADUser -SearchBase $tier0AdminsOU -Filter * `
                        -Properties AccountNotDelegated, TrustedForDelegation -ErrorAction Stop
        $state.AccountNotDelegated = @($accounts | ForEach-Object {
            @{
                DN                   = $_.DistinguishedName
                SamAccountName       = $_.SamAccountName
                AccountNotDelegated  = $_.AccountNotDelegated
                TrustedForDelegation = $_.TrustedForDelegation
            }
        })
        Write-Log "  [OK] Captured AccountNotDelegated for $($accounts.Count) Tier0 admin account(s)" -Level SUCCESS
    } catch {
        Write-Log "  [!] Could not capture AccountNotDelegated (OU may not exist yet): $($_.Exception.Message)" -Level WARN
    }

    # ---- Authentication Policy Silos ----
    try {
        $silos = @(Get-ADObject -Filter { ObjectClass -eq 'msDS-AuthNPolicySilo' } `
                      -Properties Name, DistinguishedName, 'msDS-AuthNPolicySiloMembers' -ErrorAction Stop)
        $state.AuthNPolicySilos = @($silos | ForEach-Object {
            @{
                Name    = $_.Name
                DN      = $_.DistinguishedName
                Members = @($_.'msDS-AuthNPolicySiloMembers')
            }
        })
        Write-Log "  [OK] Captured $($silos.Count) Authentication Policy Silo(s)" -Level SUCCESS
    } catch {
        Write-Log "  [!] Could not capture Authentication Policy Silos: $($_.Exception.Message)" -Level WARN
    }

    # ---- Privileged group membership ----
    $privilegedGroupNames = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins',
        'Administrators', 'Account Operators', 'Backup Operators',
        'Print Operators', 'Server Operators'
    )
    foreach ($groupName in $privilegedGroupNames) {
        try {
            $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Properties SID -ErrorAction SilentlyContinue
            if (-not $group) { continue }
            $members = @(Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue)
            $state.PrivilegedGroups += @{
                GroupName = $groupName
                SID       = $group.SID.Value
                Members   = @($members | ForEach-Object {
                    @{
                        DN             = $_.distinguishedName
                        SamAccountName = $_.SamAccountName
                        SID            = $_.SID.Value
                        ObjectClass    = $_.objectClass
                    }
                })
            }
        } catch {
            Write-Log "  [!] Could not capture group '$groupName': $($_.Exception.Message)" -Level WARN
        }
    }
    if ($state.PrivilegedGroups.Count -gt 0) {
        Write-Log "  [OK] Captured privileged group memberships ($($state.PrivilegedGroups.Count) groups)" -Level SUCCESS
    }

    $state | ConvertTo-Json -Depth 10 | Set-Content -Path $backupFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Write-Log "[OK] State baseline saved" -Level SUCCESS
    return $backupFile
}

function Get-LatestStateBackup {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$BackupDirectory)
    if (-not (Test-Path $BackupDirectory)) { return $null }
    return Get-ChildItem -Path $BackupDirectory -Filter 'state_backup_*.json' |
           Sort-Object LastWriteTime -Descending |
           Select-Object -First 1
}

function Show-StateBackup {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$BackupFile)
    if (-not (Test-Path $BackupFile)) {
        Write-Log "Backup file not found: $BackupFile" -Level ERROR
        return
    }
    $state = Get-Content -Path $BackupFile -Raw | ConvertFrom-Json
    Write-Log "`n=== State Backup ===" -Level INFO -Color Cyan
    Write-Log "Timestamp : $($state.Timestamp)" -Level INFO
    Write-Log "Domain    : $($state.TargetDomain)" -Level INFO
    Write-Log "RootDN    : $($state.RootDN)" -Level INFO

    Write-Log "OUs:" -Level INFO
    foreach ($ou in $state.OUs) {
        $marker = if ($ou.ExistedBefore) { '[existing]' } else { '[absent]  ' }
        Write-Log "  $marker $($ou.DN)" -Level INFO
    }

    Write-Log "Groups:" -Level INFO
    foreach ($g in $state.Groups) {
        $marker = if ($g.ExistedBefore) { '[existing]' } else { '[absent]  ' }
        Write-Log "  $marker $($g.Name)" -Level INFO
    }

    if ($state.AccountNotDelegated -and $state.AccountNotDelegated.Count -gt 0) {
        Write-Log "AccountNotDelegated ($($state.AccountNotDelegated.Count) account(s)):" -Level INFO
        foreach ($a in $state.AccountNotDelegated) {
            Write-Log "  $($a.SamAccountName) : AccountNotDelegated=$($a.AccountNotDelegated)" -Level INFO
        }
    }

    if ($state.AuthNPolicySilos -and $state.AuthNPolicySilos.Count -gt 0) {
        Write-Log "Authentication Policy Silos ($($state.AuthNPolicySilos.Count)):" -Level INFO
        foreach ($s in $state.AuthNPolicySilos) {
            Write-Log "  $($s.Name)  ($($s.Members.Count) member(s))" -Level INFO
        }
    }

    if ($state.PrivilegedGroups -and $state.PrivilegedGroups.Count -gt 0) {
        Write-Log "Privileged group memberships:" -Level INFO
        foreach ($g in $state.PrivilegedGroups) {
            Write-Log "  $($g.GroupName) : $($g.Members.Count) member(s)" -Level INFO
        }
    }
}

# =============================================================================
# Compare-StateBackup
# =============================================================================

function Compare-StateBackup {
    <#
    .SYNOPSIS
        Compare a saved state baseline to current AD state and return a diff.
        Read-only. Safe to call any time.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$BackupFile
    )

    if (-not (Test-Path $BackupFile)) {
        throw "Backup file not found: $BackupFile"
    }
    $state = Get-Content -Path $BackupFile -Raw | ConvertFrom-Json
    $diff = [ordered]@{
        BackupFile               = $BackupFile
        Timestamp                = $state.Timestamp
        DomainAttrs              = @()   # @{ Name; SavedValue; CurrentValue }
        OUsToDelete              = @()   # OUs absent in baseline but present now
        GroupsToDelete           = @()   # groups absent in baseline but present now
        LinksToRemove            = @()   # @{ OU; GPO } added since baseline
        LinksToReadd             = @()   # @{ OU; GPO } removed since baseline
        AccountDelegationChanges = @()   # @{ DN; SamAccountName; SavedValue; CurrentValue }
        SilosToDelete            = @()   # silo DNs absent in baseline but present now
        PrivGroupMembersToRemove = @()   # @{ GroupName; GroupSID; DN; SamAccountName; SID }
        PrivGroupMembersToReadd  = @()   # idem
        Notes                    = @()
    }

    # ---- Domain attributes ----
    if ($state.DomainObject) {
        try {
            $current = Get-ADObject -Identity $state.RootDN `
                           -Properties 'ms-DS-MachineAccountQuota', 'msDS-Other-Settings' -ErrorAction Stop
            $savedMaq   = $state.DomainObject.'ms-DS-MachineAccountQuota'
            $currentMaq = $current.'ms-DS-MachineAccountQuota'
            if ($savedMaq -ne $currentMaq) {
                $diff.DomainAttrs += [PSCustomObject]@{
                    Name = 'ms-DS-MachineAccountQuota'
                    SavedValue = $savedMaq; CurrentValue = $currentMaq; ToRestore = $true
                }
            }
            $savedOther       = @($state.DomainObject.'msDS-Other-Settings')
            $currentOther     = @($current.'msDS-Other-Settings')
            $addedSinceBackup = $currentOther | Where-Object { $_ -and ($_ -notin $savedOther) }
            if ($addedSinceBackup) {
                $diff.DomainAttrs += [PSCustomObject]@{
                    Name = 'msDS-Other-Settings'
                    SavedValue = $savedOther; CurrentValue = $currentOther; ToRestore = $true
                }
            }
        } catch {
            $diff.Notes += "Could not read current domain attributes: $($_.Exception.Message)"
        }
    }

    # ---- OUs ----
    foreach ($ou in $state.OUs) {
        $existsNow = $false
        try { Get-ADOrganizationalUnit -Identity $ou.DN -ErrorAction Stop | Out-Null; $existsNow = $true } catch { }
        if (-not $ou.ExistedBefore -and $existsNow) { $diff.OUsToDelete += $ou.DN }
        if ($ou.ExistedBefore -and -not $existsNow) {
            $diff.Notes += "OU was present in baseline but is now missing: $($ou.DN). Manual recreation required."
        }
    }

    # ---- Groups ----
    foreach ($g in $state.Groups) {
        $existsNow = $null -ne (Get-ADGroup -Filter "Name -eq '$($g.Name)'" -ErrorAction SilentlyContinue)
        if (-not $g.ExistedBefore -and $existsNow) { $diff.GroupsToDelete += $g.Name }
    }

    # ---- GPO links ----
    foreach ($linkSet in $state.GPOLinks) {
        $savedNames = @()
        if ($linkSet.Links) { $savedNames = @($linkSet.Links | ForEach-Object { $_.DisplayName }) }
        try {
            $currentLinks = (Get-GPInheritance -Target $linkSet.Target -Domain $state.TargetDomain -ErrorAction Stop).GpoLinks
            $currentNames = @($currentLinks | ForEach-Object { $_.DisplayName })
            foreach ($n in $currentNames) {
                if ($n -notin $savedNames) { $diff.LinksToRemove += [PSCustomObject]@{ OU = $linkSet.Target; GPO = $n } }
            }
            foreach ($n in $savedNames) {
                if ($n -notin $currentNames) { $diff.LinksToReadd += [PSCustomObject]@{ OU = $linkSet.Target; GPO = $n } }
            }
        } catch { }
    }

    # ---- AccountNotDelegated ----
    if ($state.AccountNotDelegated -and $state.AccountNotDelegated.Count -gt 0) {
        foreach ($saved in $state.AccountNotDelegated) {
            try {
                $current = Get-ADUser -Identity $saved.DN -Properties AccountNotDelegated -ErrorAction Stop
                if ($current.AccountNotDelegated -ne [bool]$saved.AccountNotDelegated) {
                    $diff.AccountDelegationChanges += [PSCustomObject]@{
                        DN             = $saved.DN
                        SamAccountName = $saved.SamAccountName
                        SavedValue     = [bool]$saved.AccountNotDelegated
                        CurrentValue   = $current.AccountNotDelegated
                    }
                }
            } catch {
                $diff.Notes += "Could not check AccountNotDelegated for $($saved.SamAccountName): $($_.Exception.Message)"
            }
        }
    }

    # ---- Authentication Policy Silos ----
    if ($null -ne $state.AuthNPolicySilos) {
        $savedSiloNames = @($state.AuthNPolicySilos | ForEach-Object { $_.Name })
        try {
            $currentSilos = @(Get-ADObject -Filter { ObjectClass -eq 'msDS-AuthNPolicySilo' } `
                                  -Properties Name, DistinguishedName -ErrorAction Stop)
            foreach ($silo in $currentSilos) {
                if ($silo.Name -notin $savedSiloNames) { $diff.SilosToDelete += $silo.DistinguishedName }
            }
            $currentSiloNames = @($currentSilos | ForEach-Object { $_.Name })
            foreach ($saved in $state.AuthNPolicySilos) {
                if ($saved.Name -notin $currentSiloNames) {
                    $diff.Notes += "Authentication Policy Silo '$($saved.Name)' was present in baseline but is now missing."
                }
            }
        } catch {
            $diff.Notes += "Could not enumerate Authentication Policy Silos: $($_.Exception.Message)"
        }
    }

    # ---- Privileged group membership ----
    if ($state.PrivilegedGroups -and $state.PrivilegedGroups.Count -gt 0) {
        foreach ($savedGroup in $state.PrivilegedGroups) {
            try {
                $group = Get-ADGroup -Identity $savedGroup.SID -ErrorAction SilentlyContinue
                if (-not $group) { continue }
                $currentMembers = @(Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue)
                $currentSids    = @($currentMembers | ForEach-Object { $_.SID.Value })
                $savedSids      = @($savedGroup.Members | ForEach-Object { $_.SID })

                foreach ($m in $currentMembers) {
                    if ($m.SID.Value -notin $savedSids) {
                        $diff.PrivGroupMembersToRemove += [PSCustomObject]@{
                            GroupName      = $savedGroup.GroupName
                            GroupSID       = $savedGroup.SID
                            DN             = $m.distinguishedName
                            SamAccountName = $m.SamAccountName
                            SID            = $m.SID.Value
                        }
                    }
                }
                foreach ($saved in $savedGroup.Members) {
                    if ($saved.SID -notin $currentSids) {
                        $diff.PrivGroupMembersToReadd += [PSCustomObject]@{
                            GroupName      = $savedGroup.GroupName
                            GroupSID       = $savedGroup.SID
                            DN             = $saved.DN
                            SamAccountName = $saved.SamAccountName
                            SID            = $saved.SID
                        }
                    }
                }
            } catch {
                $diff.Notes += "Could not compare group '$($savedGroup.GroupName)': $($_.Exception.Message)"
            }
        }
    }

    return [PSCustomObject]$diff
}

# =============================================================================
# Restore-StateBackup
# =============================================================================

function Restore-StateBackup {
    <#
    .SYNOPSIS Restore AD to the state captured in a backup file (best-effort).
    .DESCRIPTION
        Loads a state_backup_*.json and reverses changes. Set -WhatIf to preview.
        Use -All or individual -Include* switches to select what to restore.
    .PARAMETER BackupFile
        Path to a state_backup_*.json file.
    .PARAMETER IncludeDomainAttrs
        Restore ms-DS-MachineAccountQuota and msDS-Other-Settings.
    .PARAMETER IncludeOUs
        Delete OUs created since the backup (only if empty).
    .PARAMETER IncludeGroups
        Delete managed groups created since the backup.
    .PARAMETER IncludeGPOLinks
        Restore GPO links to the baseline state.
    .PARAMETER IncludeAccountDelegation
        Revert AccountNotDelegated flags on Tier0 admin accounts.
    .PARAMETER IncludeSilos
        Delete Authentication Policy Silos created since the backup.
    .PARAMETER IncludePrivilegedGroups
        Remove members added to privileged groups since backup; re-add removed members.
        Never removes the built-in Administrator account (RID 500).
    .PARAMETER All
        Equivalent to enabling all -Include* switches.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [string]$BackupFile,
        [switch]$IncludeDomainAttrs,
        [switch]$IncludeOUs,
        [switch]$IncludeGroups,
        [switch]$IncludeGPOLinks,
        [switch]$IncludeAccountDelegation,
        [switch]$IncludeSilos,
        [switch]$IncludePrivilegedGroups,
        [switch]$All
    )

    if ($All) {
        $IncludeDomainAttrs       = $true
        $IncludeOUs               = $true
        $IncludeGroups            = $true
        $IncludeGPOLinks          = $true
        $IncludeAccountDelegation = $true
        $IncludeSilos             = $true
        $IncludePrivilegedGroups  = $true
    }

    Write-Log "`n=== Restore from backup: $BackupFile ===" -Level INFO
    $state = Get-Content -Path $BackupFile -Raw | ConvertFrom-Json
    Write-Log "Backup timestamp : $($state.Timestamp)" -Level INFO
    Write-Log "Target domain    : $($state.TargetDomain)" -Level INFO

    $diff = Compare-StateBackup -BackupFile $BackupFile

    Write-Log "`n--- Diff summary ---" -Level INFO
    Write-Log "Domain attributes to restore    : $($diff.DomainAttrs.Count)" -Level INFO
    Write-Log "OUs to delete (created since)   : $($diff.OUsToDelete.Count)" -Level INFO
    Write-Log "Groups to delete                : $($diff.GroupsToDelete.Count)" -Level INFO
    Write-Log "GPO links to remove             : $($diff.LinksToRemove.Count)" -Level INFO
    Write-Log "GPO links to re-add             : $($diff.LinksToReadd.Count)" -Level INFO
    Write-Log "AccountNotDelegated changes     : $($diff.AccountDelegationChanges.Count)" -Level INFO
    Write-Log "Silos to delete (created since) : $($diff.SilosToDelete.Count)" -Level INFO
    Write-Log "Priv group members to remove    : $($diff.PrivGroupMembersToRemove.Count)" -Level INFO
    Write-Log "Priv group members to re-add    : $($diff.PrivGroupMembersToReadd.Count)" -Level INFO
    foreach ($n in $diff.Notes) { Write-Log "Note: $n" -Level WARN }

    # ---- [1/7] Domain attributes ----
    if ($IncludeDomainAttrs -and $diff.DomainAttrs.Count -gt 0) {
        Write-Log "`n[1/7] Restoring domain attributes" -Level INFO
        foreach ($attr in $diff.DomainAttrs) {
            if ($PSCmdlet.ShouldProcess("$($state.RootDN) ($($attr.Name))", "Restore to baseline value")) {
                try {
                    if ($attr.Name -eq 'ms-DS-MachineAccountQuota') {
                        Set-ADObject -Identity $state.RootDN -Replace @{ 'ms-DS-MachineAccountQuota' = [int]$attr.SavedValue }
                    } elseif ($attr.Name -eq 'msDS-Other-Settings') {
                        Set-ADObject -Identity $state.RootDN -Replace @{ 'msDS-Other-Settings' = @($attr.SavedValue) }
                    }
                    Write-Log "  [OK] Restored $($attr.Name)" -Level SUCCESS
                } catch {
                    Write-Log "  [X] Failed: $($_.Exception.Message)" -Level ERROR
                }
            }
        }
    }

    # ---- [2/7] GPO links ----
    if ($IncludeGPOLinks) {
        if ($diff.LinksToRemove.Count -gt 0) {
            Write-Log "`n[2/7] Removing GPO links added since backup" -Level INFO
            foreach ($l in $diff.LinksToRemove) {
                if ($PSCmdlet.ShouldProcess($l.OU, "Unlink GPO '$($l.GPO)'")) {
                    try {
                        Remove-GPLink -Name $l.GPO -Target $l.OU -Domain $state.TargetDomain -ErrorAction Stop | Out-Null
                        Write-Log "  [OK] Unlinked $($l.GPO) from $($l.OU)" -Level SUCCESS
                    } catch {
                        Write-Log "  [X] $($_.Exception.Message)" -Level ERROR
                    }
                }
            }
        }
        if ($diff.LinksToReadd.Count -gt 0) {
            Write-Log "`n[2b/7] Re-adding GPO links removed since backup" -Level INFO
            foreach ($l in $diff.LinksToReadd) {
                if ($PSCmdlet.ShouldProcess($l.OU, "Re-link GPO '$($l.GPO)'")) {
                    try {
                        New-GPLink -Name $l.GPO -Target $l.OU -Domain $state.TargetDomain -ErrorAction Stop | Out-Null
                        Write-Log "  [OK] Re-linked $($l.GPO) to $($l.OU)" -Level SUCCESS
                    } catch {
                        Write-Log "  [X] $($_.Exception.Message) (GPO may have been deleted)" -Level ERROR
                    }
                }
            }
        }
    }

    # ---- [3/7] Managed groups ----
    if ($IncludeGroups -and $diff.GroupsToDelete.Count -gt 0) {
        Write-Log "`n[3/7] Deleting managed groups created since backup" -Level INFO
        foreach ($groupName in $diff.GroupsToDelete) {
            try {
                $g = Get-ADGroup -Filter "Name -eq '$groupName'" -Properties Members -ErrorAction Stop
                $memberCount = if ($g.Members) { $g.Members.Count } else { 0 }
                if ($memberCount -gt 0) {
                    Write-Log "  [!] Skipping ${groupName}: has $memberCount member(s). Empty it first." -Level WARN
                    continue
                }
                if ($PSCmdlet.ShouldProcess($groupName, 'Delete group')) {
                    Remove-ADGroup -Identity $g -Confirm:$false -ErrorAction Stop
                    Write-Log "  [OK] Deleted group $groupName" -Level SUCCESS
                }
            } catch {
                Write-Log "  [X] $($_.Exception.Message)" -Level ERROR
            }
        }
    }

    # ---- [4/7] OUs ----
    if ($IncludeOUs -and $diff.OUsToDelete.Count -gt 0) {
        Write-Log "`n[4/7] Deleting OUs created since backup" -Level INFO
        $sortedOUs = $diff.OUsToDelete | Sort-Object { ($_.Split(',')).Count } -Descending
        foreach ($ouDN in $sortedOUs) {
            try {
                $children = Get-ADObject -SearchBase $ouDN -SearchScope OneLevel -Filter * -ErrorAction Stop
                if ($children.Count -gt 0) {
                    Write-Log "  [!] Skipping ${ouDN}: contains $($children.Count) child object(s). Move them out first." -Level WARN
                    continue
                }
                $ou = Get-ADOrganizationalUnit -Identity $ouDN -Properties ProtectedFromAccidentalDeletion -ErrorAction Stop
                if ($ou.ProtectedFromAccidentalDeletion) {
                    if ($PSCmdlet.ShouldProcess($ouDN, 'Remove accidental-deletion protection')) {
                        Set-ADOrganizationalUnit -Identity $ou -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
                    }
                }
                if ($PSCmdlet.ShouldProcess($ouDN, 'Delete empty OU')) {
                    Remove-ADOrganizationalUnit -Identity $ou -Confirm:$false -ErrorAction Stop
                    Write-Log "  [OK] Deleted OU $ouDN" -Level SUCCESS
                }
            } catch {
                Write-Log "  [X] $($_.Exception.Message)" -Level ERROR
            }
        }
    }

    # ---- [5/7] AccountNotDelegated ----
    if ($IncludeAccountDelegation -and $diff.AccountDelegationChanges.Count -gt 0) {
        Write-Log "`n[5/7] Restoring AccountNotDelegated flags" -Level INFO
        foreach ($change in $diff.AccountDelegationChanges) {
            if ($PSCmdlet.ShouldProcess($change.SamAccountName, "Set AccountNotDelegated = $($change.SavedValue)")) {
                try {
                    Set-ADUser -Identity $change.DN -AccountNotDelegated $change.SavedValue -ErrorAction Stop
                    Write-Log "  [OK] $($change.SamAccountName): AccountNotDelegated = $($change.SavedValue)" -Level SUCCESS
                } catch {
                    Write-Log "  [X] $($change.SamAccountName): $($_.Exception.Message)" -Level ERROR
                }
            }
        }
    }

    # ---- [6/7] Authentication Policy Silos ----
    if ($IncludeSilos -and $diff.SilosToDelete.Count -gt 0) {
        Write-Log "`n[6/7] Deleting Authentication Policy Silos created since backup" -Level INFO
        Write-Log "  Note: linked Authentication Policies are not removed by this step." -Level WARN
        foreach ($siloDN in $diff.SilosToDelete) {
            if ($PSCmdlet.ShouldProcess($siloDN, 'Delete Authentication Policy Silo')) {
                try {
                    Remove-ADObject -Identity $siloDN -Confirm:$false -ErrorAction Stop
                    Write-Log "  [OK] Deleted silo: $siloDN" -Level SUCCESS
                } catch {
                    Write-Log "  [X] $siloDN : $($_.Exception.Message)" -Level ERROR
                }
            }
        }
    }

    # ---- [7/7] Privileged group membership ----
    if ($IncludePrivilegedGroups) {
        if ($diff.PrivGroupMembersToRemove.Count -gt 0) {
            Write-Log "`n[7/7] Removing members added to privileged groups since backup" -Level INFO
            foreach ($m in $diff.PrivGroupMembersToRemove) {
                if ($m.SID -match '-500$') {
                    Write-Log "  [!] Skipping built-in Administrator ($($m.SamAccountName)) in $($m.GroupName)" -Level WARN
                    continue
                }
                if ($PSCmdlet.ShouldProcess($m.GroupName, "Remove $($m.SamAccountName)")) {
                    try {
                        $group = Get-ADGroup -Identity $m.GroupSID -ErrorAction Stop
                        Remove-ADGroupMember -Identity $group -Members $m.DN -Confirm:$false -ErrorAction Stop
                        Write-Log "  [OK] Removed $($m.SamAccountName) from $($m.GroupName)" -Level SUCCESS
                    } catch {
                        Write-Log "  [X] $($m.SamAccountName): $($_.Exception.Message)" -Level ERROR
                    }
                }
            }
        }
        if ($diff.PrivGroupMembersToReadd.Count -gt 0) {
            Write-Log "`n[7b/7] Re-adding members removed from privileged groups since backup" -Level INFO
            foreach ($m in $diff.PrivGroupMembersToReadd) {
                if ($PSCmdlet.ShouldProcess($m.GroupName, "Re-add $($m.SamAccountName)")) {
                    try {
                        $group = Get-ADGroup -Identity $m.GroupSID -ErrorAction Stop
                        Add-ADGroupMember -Identity $group -Members $m.DN -ErrorAction Stop
                        Write-Log "  [OK] Re-added $($m.SamAccountName) to $($m.GroupName)" -Level SUCCESS
                    } catch {
                        Write-Log "  [X] $($m.SamAccountName): $($_.Exception.Message)" -Level ERROR
                    }
                }
            }
        }
    }

    Write-Log "`n=== Restore completed ===" -Level SUCCESS
    Write-Log "Note: Recycle Bin / LAPS schema / GPO content imports / linked Auth Policies are not reversible." -Level WARN
}

# =============================================================================
# Restore-OUSecurityDescriptor
# =============================================================================

function Restore-OUSecurityDescriptor {
    <#
    .SYNOPSIS Restore an OU's ACL from a backup file produced by Backup-OUSecurityDescriptor.
    .DESCRIPTION
        Replaces the current ACL of the target OU with the saved one. Inherited ACEs are
        skipped (they re-apply automatically). Use -WhatIf to preview.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [string]$BackupFile
    )

    if (-not (Test-Path $BackupFile)) { throw "Backup file not found: $BackupFile" }
    $payload = Get-Content -Path $BackupFile -Raw | ConvertFrom-Json
    $ouDN = $payload.OUDistinguishedName
    Write-Log "`n=== Restoring ACL for $ouDN ===" -Level INFO
    Write-Log "Backup from: $($payload.Timestamp)" -Level INFO
    Write-Log "Saved ACEs : $($payload.ACEs.Count)" -Level INFO

    try {
        Get-ADOrganizationalUnit -Identity $ouDN -ErrorAction Stop | Out-Null
    } catch {
        Write-Log "  [X] OU not found: $ouDN" -Level ERROR
        return
    }

    $aclPath = "AD:$ouDN"
    $current = Get-Acl -Path $aclPath
    $rebuilt = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $rebuilt.SetSecurityDescriptorSddlForm($current.GetSecurityDescriptorSddlForm('Owner,Group'))

    foreach ($ace in $payload.ACEs) {
        if ($ace.IsInherited -eq $true) { continue }
        try {
            $sid = New-Object System.Security.Principal.NTAccount($ace.IdentityReference)
            try { $sid = $sid.Translate([System.Security.Principal.SecurityIdentifier]) } catch { }

            $rights        = [System.DirectoryServices.ActiveDirectoryRights]$ace.ActiveDirectoryRights
            $access        = [System.Security.AccessControl.AccessControlType]$ace.AccessControlType
            $inheritance   = [System.DirectoryServices.ActiveDirectorySecurityInheritance]$ace.InheritanceType
            $objectType    = [Guid]$ace.ObjectType
            $inheritedType = [Guid]$ace.InheritedObjectType

            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $sid, $rights, $access, $objectType, $inheritance, $inheritedType
            )
            $rebuilt.AddAccessRule($rule)
        } catch {
            Write-Log "  [!] Could not reconstruct ACE for $($ace.IdentityReference): $($_.Exception.Message)" -Level WARN
        }
    }

    if ($PSCmdlet.ShouldProcess($ouDN, "Replace ACL with backup from $($payload.Timestamp)")) {
        try {
            Set-Acl -Path $aclPath -AclObject $rebuilt -ErrorAction Stop
            Write-Log "  [OK] ACL restored on $ouDN" -Level SUCCESS
        } catch {
            Write-Log "  [X] Set-Acl failed: $($_.Exception.Message)" -Level ERROR
            throw
        }
    }
}

# =============================================================================
# Restore-PreWindows2000Members
# =============================================================================

function Restore-PreWindows2000Members {
    <#
    .SYNOPSIS Re-add members to 'Pre-Windows 2000 Compatible Access' from a backup file.
    .DESCRIPTION
        Reads a JSON backup produced by Lock-PreWindows2000Group and adds each member back.
        Members already present are skipped.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [string]$BackupFile
    )

    if (-not (Test-Path $BackupFile)) { throw "Backup file not found: $BackupFile" }
    $members = Get-Content -Path $BackupFile -Raw | ConvertFrom-Json
    $sid = 'S-1-5-32-554'

    Write-Log "`n=== Restoring Pre-Windows 2000 group members ===" -Level INFO
    try {
        $group = Get-ADGroup -Identity $sid -ErrorAction Stop
    } catch {
        Write-Log "  [X] Could not resolve group SID $sid : $($_.Exception.Message)" -Level ERROR
        return
    }

    $current     = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
    $currentSids = @($current | ForEach-Object { $_.SID.Value })

    foreach ($m in $members) {
        if ($m.SID -and ($m.SID.Value -in $currentSids -or $m.SID -in $currentSids)) {
            Write-Log "  [=] Already member: $($m.SamAccountName)" -Level INFO
            continue
        }
        if ($PSCmdlet.ShouldProcess($m.SamAccountName, 'Add to Pre-Windows 2000 group')) {
            try {
                Add-ADGroupMember -Identity $group -Members $m.distinguishedName -ErrorAction Stop
                Write-Log "  [OK] Added: $($m.SamAccountName)" -Level SUCCESS
            } catch {
                Write-Log "  [X] $($m.SamAccountName): $($_.Exception.Message)" -Level ERROR
            }
        }
    }
}

# =============================================================================
# Get-AvailableBackups
# =============================================================================

function Get-AvailableBackups {
    <#
    .SYNOPSIS List backup files in the standard backup directories.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$BackupDirectory
    )
    $result = [ordered]@{
        State      = @()
        ACL        = @()
        PreWin2000 = @()
    }
    if (Test-Path $BackupDirectory) {
        $result.State      = @(Get-ChildItem -Path $BackupDirectory -Filter 'state_backup_*.json'       -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        $result.PreWin2000 = @(Get-ChildItem -Path $BackupDirectory -Filter 'preWin2000_members_*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        $aclDir = Join-Path $BackupDirectory 'acl'
        if (Test-Path $aclDir) {
            $result.ACL = @(Get-ChildItem -Path $aclDir -Filter 'acl_*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        }
    }
    return [PSCustomObject]$result
}

Export-ModuleMember -Function `
    New-StateBackup, Get-LatestStateBackup, Show-StateBackup, `
    Compare-StateBackup, Restore-StateBackup, `
    Restore-OUSecurityDescriptor, `
    Restore-PreWindows2000Members, `
    Get-AvailableBackups
