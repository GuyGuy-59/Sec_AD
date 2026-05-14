<#
.SYNOPSIS
    Active Directory hardening: domain-level security settings, tier ACL delegation,
    Authentication Policy Silos, Pre-Windows 2000 lockdown, privileged group audit,
    and sensitive-account flagging.

.DESCRIPTION
    Applies non-GPO domain security settings and defense-in-depth controls on top of
    the tiered OU structure created by ADStructure.psm1. All modification functions
    support -WhatIf via SupportsShouldProcess.

    Functions exported:
      - Set-ADSIUnauthenticatedBind      : set DenyUnauthenticatedBind=1 on the Directory Service object
      - Set-msDSMachineAccountQuota      : set ms-DS-MachineAccountQuota to 0 (prevent non-admin machine joins)
      - Set-KerberosEncryptionTypes      : restrict krbtgt and DCs to AES-128/AES-256 (disable RC4/DES)
      - Enable-RecycleBin                : enable the AD Recycle Bin (requires Forest FL >= 2008 R2)
      - Enable-LAPS                      : update the LAPS AD schema and set delegation on the Tier2 Workstations OU
      - Enable-BitLocker                 : install BitLocker RSAT management tools on the DC
      - Set-TierOUDelegation             : delegate FullControl to a tier admin group, deny cross-tier writes
      - Backup-OUSecurityDescriptor      : export current ACL of an OU to JSON for rollback
      - New-Tier0AuthenticationPolicySilo : create/update policy + silo from Silo_config.json; additive member assignment (Audit/Enforce mode)
      - Add-Tier0SiloMember              : assign Tier 0 admins/users to the silo
      - Lock-PreWindows2000Group         : empty 'Pre-Windows 2000 Compatible Access' membership
      - Get-PrivilegedGroupAudit         : audit DA/EA/SA membership with recommendations
      - Remove-PrivilegedGroupMember     : safely remove a member (refuses to remove built-in Administrator by default)
      - Set-Tier0AccountSensitive        : mark Tier 0 user accounts as sensitive (cannot be delegated)
#>


function Set-ADSIUnauthenticatedBind {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory=$true)] [string]$TargetDomain
    )

    try {
        Write-Log "`n=== Configuring ADSI Unauthenticated Bind ===" -Level INFO -Color Cyan
        Write-Log "Target Domain: $TargetDomain" -Level INFO

        Write-Log "`n-> Building Directory Service DN..." -Level INFO
        $domainDN = "DC=" + ($TargetDomain -replace "\.", ",DC=")
        $directoryServiceDn = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$domainDN"

        Write-Log "-> Retrieving Directory Service object..." -Level INFO
        $directoryService = Get-ADObject -Identity $directoryServiceDn -Properties "msDS-Other-Settings"

        Write-Log "`nCurrent Configuration:" -Level INFO
        Write-Log "  msDS-Other-Settings: $($directoryService."msDS-Other-Settings")" -Level DEBUG

        $currentValue = $directoryService."msDS-Other-Settings"

        if ($currentValue -notcontains "DenyUnauthenticatedBind=1") {
            $newValue = if ([string]::IsNullOrEmpty($currentValue)) {
                @("DenyUnauthenticatedBind=1")
            } else {
                $currentValue + "DenyUnauthenticatedBind=1"
            }

            if ($PSCmdlet.ShouldProcess($directoryServiceDn, 'Set DenyUnauthenticatedBind=1')) {
                Set-ADObject -Identity $directoryServiceDn -Replace @{ "msDS-Other-Settings" = $newValue }
                Write-Log "[OK] Successfully configured DenyUnauthenticatedBind=1" -Level SUCCESS
            }
        } else {
            Write-Log "[OK] DenyUnauthenticatedBind=1 is already configured" -Level INFO
        }
    } catch {
        Write-Error "[X] Configuration failed: $_"
        throw
    }
}

function Set-msDSMachineAccountQuota {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory=$true)] [string]$TargetDomain
    )

    try {
        Write-Log "`n=== Configuring ms-DS-MachineAccountQuota ===" -Level INFO -Color Cyan
        Write-Log "Target Domain: $TargetDomain" -Level INFO

        Write-Log "`n-> Building domain DN..." -Level INFO
        $domainDN = "DC=" + ($TargetDomain -replace '\.', ',DC=')

        Write-Log "-> Retrieving current ms-DS-MachineAccountQuota value..." -Level INFO
        $currentQuota = (Get-ADObject -Identity $domainDN -Properties "ms-DS-MachineAccountQuota")."ms-DS-MachineAccountQuota"

        Write-Log "Current ms-DS-MachineAccountQuota value: $currentQuota" -Level INFO

        if ($currentQuota -ne 0) {
            if ($PSCmdlet.ShouldProcess($domainDN, 'Set ms-DS-MachineAccountQuota = 0')) {
                Write-Log "[!] Updating ms-DS-MachineAccountQuota to 0..." -Level WARN
                Set-ADObject -Identity $domainDN -Replace @{ "ms-DS-MachineAccountQuota" = 0 }
                Write-Log "[OK] Successfully set ms-DS-MachineAccountQuota to 0" -Level SUCCESS
            }
        } else {
            Write-Log "[OK] ms-DS-MachineAccountQuota is already set to 0" -Level INFO
        }
    } catch {
        Write-Error "[X] Configuration failed: $_"
        throw
    }
}

function Enable-RecycleBin {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory=$true)] [string]$TargetDomain,
        [Parameter(Mandatory=$true)] [hashtable]$FunctionalLevels
    )

    Write-Log "`n=== Configuring AD Recycle Bin ===" -Level INFO -Color Cyan

    try {
        Write-Log "-> Checking forest functional level..." -Level INFO
        Write-Log "  Current level: $($FunctionalLevels.ForestLevel)" -Level DEBUG
        if ($FunctionalLevels.ForestLevel -lt 2008) {
            Write-Log "[!] Forest functional level is not sufficient (minimum: Windows Server 2008 R2)." -Level WARN
            Write-Log "[!] Please raise the forest functional level before enabling the Recycle Bin." -Level WARN
            Write-Log "[!] Skipping Recycle Bin configuration. Other tasks will continue." -Level WARN
            return
        }

        $recycleBinFeature = Get-ADOptionalFeature -Filter {Name -eq 'Recycle Bin Feature'}

        if ($recycleBinFeature.EnabledScopes) {
            Write-Log "[OK] Active Directory Recycle Bin is already enabled." -Level SUCCESS
        } else {
            Write-Log "[!] Enabling Active Directory Recycle Bin..." -Level WARN
            try {
                if ($PSCmdlet.ShouldProcess($TargetDomain, 'Enable AD Recycle Bin (irreversible)')) {
                    Enable-ADOptionalFeature -Identity $recycleBinFeature -Scope ForestOrConfigurationSet -Target $TargetDomain -Confirm:$false
                    Write-Log "[OK] Active Directory Recycle Bin has been successfully enabled." -Level SUCCESS
                }
            } catch {
                Write-Log "[X] An error occurred while enabling the Recycle Bin: $($_.Exception.Message)" -Level ERROR
            }
        }

        Write-Log "-> Performing final check of Recycle Bin status..." -Level INFO -Color Cyan
        $recycleBinFeature = Get-ADOptionalFeature -Filter {Name -eq 'Recycle Bin Feature'}
        if ($recycleBinFeature.EnabledScopes) {
            Write-Log "[OK] Active Directory Recycle Bin is enabled." -Level SUCCESS
        } else {
            Write-Log "[X] Active Directory Recycle Bin could not be enabled." -Level ERROR
        }
    } catch {
        Write-Error "[X] Recycle Bin configuration failed: $_"
        throw
    }
}

function Enable-LAPS {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory=$true)] [string]$TargetDomain
    )

    try {
        Write-Log "`n=== Configuring LAPS ===" -Level INFO -Color Cyan
        Write-Log "Target Domain: $TargetDomain" -Level INFO

        $lapsFeature = Get-Command -Module LAPS
        if ($lapsFeature) {
            if ($PSCmdlet.ShouldProcess('AD Schema', 'Update LAPS schema')) {
                Update-LapsADSchema -Verbose -Confirm:$false
                Write-Log "[!] Updating LAPS AD Schema..." -Level WARN
            }

            $domainDN = (Get-ADDomain $TargetDomain).DistinguishedName
            $workstationsOU = @(
                @{ Name = "$TargetDomain\LAPS-Pwd-Read-T2"; Path = "OU=Workstations,OU=_Tier2,$domainDN" }
                @{ Name = "$TargetDomain\LAPS-Pwd-Read-T0"; Path = "OU=PAW,OU=_Tier0,$domainDN" }
            )
            foreach ($w in $workstationsOU) {
            
                Set-LapsADComputerSelfPermission -Identity $w.Path
                Write-Host "[OK] Setting LAPS AD Computer Self Permission..." -ForegroundColor Yellow
                
                Set-LapsADReadPasswordPermission -Identity $w.Path -AllowedPrincipals $w.Name
                Write-Host "[OK] Setting LAPS password read permissions..." -ForegroundColor Yellow

                Write-Host "`n[!] IMPORTANT:" -ForegroundColor Yellow
                Write-Host "The LAPS-Enabled GPO must be modified to add $w.Name" -ForegroundColor Yellow
                Write-Host "in the 'Configure authorized password decryptors' setting" -ForegroundColor Yellow
            }
        } else {
            Write-Log "[X] LAPS is not installed." -Level ERROR
        }
    } catch {
        Write-Error "[X] LAPS configuration failed: $_"
        throw
    }
}

function Set-KerberosEncryptionTypes {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    try {
        Write-Log "`n=== Setting msDS-SupportedEncryptionTypes for krbtgt and Domain Controllers ===" -Level INFO -Color Cyan

        $encryptionTypes = @{
            0x1  = "DES_CBC_CRC"
            0x2  = "DES_CBC_MD5"
            0x4  = "RC4"
            0x8  = "AES 128"
            0x10 = "AES 256"
        }
        $newEncryptionTypes = 0x18

        function Update-EncryptionTypes {
            param(
                [Parameter(Mandatory=$true)] [Microsoft.ActiveDirectory.Management.ADObject]$Account,
                [Parameter(Mandatory=$true)] [string]$AccountName
            )

            $currentEncryptionTypes = if ($null -eq $Account."msDS-SupportedEncryptionTypes") { 0 } else { $Account."msDS-SupportedEncryptionTypes" }

            Write-Log "`n-> $AccountName" -Level INFO
            Write-Log "  Current Encryption Types (Decimal: $currentEncryptionTypes, Hex: 0x$($currentEncryptionTypes.ToString('X')))" -Level DEBUG
            Write-Log "  Supported Encryption Types:" -Level DEBUG

            $supportedTypes = @()
            foreach ($type in $encryptionTypes.GetEnumerator()) {
                if ($currentEncryptionTypes -band $type.Key) { $supportedTypes += $type.Value }
            }

            if ($supportedTypes.Count -eq 0) {
                Write-Log "    Not defined - defaults to RC4_HMAC_MD5" -Level DEBUG
            } else {
                $supportedTypes | ForEach-Object { Write-Log "    $_" -Level DEBUG }
            }

            if ($currentEncryptionTypes -ne $newEncryptionTypes) {
                Set-ADObject -Identity $Account -Replace @{"msDS-SupportedEncryptionTypes" = $newEncryptionTypes}
                if ($?) {
                    $updatedAccount = Get-ADObject -Identity $Account -Property msDS-SupportedEncryptionTypes
                    $newValue = $updatedAccount."msDS-SupportedEncryptionTypes"
                    Write-Log "  [OK] msDS-SupportedEncryptionTypes updated to:" -Level SUCCESS
                    Write-Log "    Decimal: $newValue  Hex: 0x$($newValue.ToString('X'))" -Level DEBUG
                    $supportedTypes = @()
                    foreach ($type in $encryptionTypes.GetEnumerator()) {
                        if ($newValue -band $type.Key) { $supportedTypes += $type.Value }
                    }
                    $supportedTypes | ForEach-Object { Write-Log "      $_" -Level DEBUG }
                } else {
                    Write-Log "  [X] Failed to update msDS-SupportedEncryptionTypes." -Level ERROR
                }
            } else {
                Write-Log "  [OK] Encryption types already configured correctly" -Level SUCCESS
            }
        }

        Write-Log "`n=== Configuring krbtgt account ===" -Level INFO -Color Cyan
        $krbtgtAccount = Get-ADObject -Filter {Name -eq "krbtgt"} -Property msDS-SupportedEncryptionTypes
        if ($krbtgtAccount) {
            Update-EncryptionTypes -Account $krbtgtAccount -AccountName "krbtgt"
        } else {
            Write-Log "[X] krbtgt account not found." -Level ERROR
        }

        Write-Log "`n=== Configuring Domain Controllers ===" -Level INFO -Color Cyan
        $domainControllers = Get-ADComputer -Filter {PrimaryGroupID -eq 516} -Property msDS-SupportedEncryptionTypes

        if ($domainControllers) {
            Write-Log "Found $($domainControllers.Count) Domain Controller(s)" -Level INFO
            foreach ($dc in $domainControllers) {
                Update-EncryptionTypes -Account $dc -AccountName $dc.Name
            }
        } else {
            Write-Log "[!] No Domain Controllers found." -Level WARN
        }
    } catch {
        Write-Error "[X] Failed to set msDS-SupportedEncryptionTypes: $_"
        throw
    }
}

function Enable-Bitlocker {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    try {
        Write-Log "`n=== Installing BitLocker RSAT Features ===" -Level INFO -Color Cyan

        $requiredFeatures = @(
            "RSAT-Feature-Tools-BitLocker",
            "RSAT-Feature-Tools-BitLocker-RemoteAdminTool",
            "RSAT-Feature-Tools-BitLocker-BdeAducExt"
        )

        Write-Log "-> Checking and installing BitLocker RSAT features..." -Level INFO

        foreach ($feature in $requiredFeatures) {
            $installed = Get-WindowsFeature -Name $feature -ErrorAction SilentlyContinue
            if (-not $installed -or $installed.InstallState -ne "Installed") {
                Write-Log "  Installing: $feature" -Level DEBUG
                if ($PSCmdlet.ShouldProcess($feature, 'Install-WindowsFeature')) {
                    Install-WindowsFeature -Name $feature -IncludeAllSubFeature -IncludeManagementTools
                    Write-Log "  [OK] $feature installed successfully" -Level SUCCESS
                }
            } else {
                Write-Log "  [OK] $feature is already installed" -Level SUCCESS
            }
        }

        Write-Log "`n[OK] All BitLocker RSAT features are now installed!" -Level SUCCESS
    } catch {
        Write-Error "[X] Failed to install BitLocker RSAT features: $_"
        throw
    }
}


function Backup-OUSecurityDescriptor {
    <#
    .SYNOPSIS Save current ACL of an OU to JSON for potential rollback.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$OUDistinguishedName,
        [Parameter(Mandatory)] [string]$BackupDirectory
    )

    if (-not (Test-Path $BackupDirectory)) {
        New-Item -ItemType Directory -Path $BackupDirectory -Force -WhatIf:$false -Confirm:$false | Out-Null
    }
    $safeDN    = $OUDistinguishedName -replace '[,=\s]', '_'
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $file      = Join-Path $BackupDirectory "acl_${safeDN}_${timestamp}.json"

    try {
        $acl = Get-Acl -Path "AD:$OUDistinguishedName" -ErrorAction Stop
        $entries = foreach ($ace in $acl.Access) {
            [PSCustomObject]@{
                IdentityReference  = $ace.IdentityReference.Value
                ActiveDirectoryRights = $ace.ActiveDirectoryRights.ToString()
                AccessControlType  = $ace.AccessControlType.ToString()
                ObjectType         = $ace.ObjectType.ToString()
                InheritedObjectType = $ace.InheritedObjectType.ToString()
                InheritanceType    = $ace.InheritanceType.ToString()
                IsInherited        = $ace.IsInherited
            }
        }
        $payload = [PSCustomObject]@{
            Timestamp           = (Get-Date -Format 'o')
            OUDistinguishedName = $OUDistinguishedName
            Owner               = $acl.Owner
            ACEs                = @($entries)
        }
        $payload | ConvertTo-Json -Depth 10 | Set-Content -Path $file -Encoding UTF8 -WhatIf:$false -Confirm:$false
        Write-Log "  [OK] ACL backup: $file" -Level SUCCESS
        return $file
    } catch {
        Write-Log "  [X] ACL backup failed for ${OUDistinguishedName}: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

function Set-TierOUDelegation {
    <#
    .SYNOPSIS Delegate FullControl on a tier OU to its admin group, and deny writes from other tier admin groups.
    .DESCRIPTION
        Implements the cross-tier isolation principle: only the admin group for tier N
        can modify objects in tier N's OU. Other tier admin groups receive an explicit Deny on Write.
        Run after Initialize-ADStructure.
    .PARAMETER TierName
        e.g. Tier0, Tier1, Tier2, Tier1_Legacy
    .PARAMETER AdminGroupName
        SamAccountName of the group that owns this tier (will be created if missing).
    .PARAMETER OtherTierAdminGroups
        SamAccountNames of admin groups for the other tiers (Deny applied).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)] [string]$TierName,
        [Parameter(Mandatory)] [string]$RootDN,
        [Parameter(Mandatory)] [string]$AdminGroupName,
        [Parameter()]          [string[]]$OtherTierAdminGroups = @(),
        [Parameter()]          [string]$BackupDirectory
    )

    Write-Log "`n=== Delegating $TierName OU ===" -Level INFO
    $tierOU = "OU=_$TierName,$RootDN"

    try {
        $ouObj = Get-ADOrganizationalUnit -Identity $tierOU -ErrorAction Stop
    } catch {
        Write-Log "  [X] Tier OU not found: $tierOU" -Level ERROR
        Write-Log "      Run Initialize-ADStructure first." -Level ERROR
        return
    }

    # Backup ACL before changes
    if ($BackupDirectory) {
        Backup-OUSecurityDescriptor -OUDistinguishedName $tierOU -BackupDirectory $BackupDirectory | Out-Null
    }

    # Resolve admin group SID (create if missing under Groups OU of the tier)
    $adminGroup = Get-ADGroup -Filter "Name -eq '$AdminGroupName'" -ErrorAction SilentlyContinue
    if (-not $adminGroup) {
        $groupsOU = "OU=Groups,$tierOU"
        Write-Log "  -> Creating admin group $AdminGroupName in $groupsOU" -Level INFO
        if ($PSCmdlet.ShouldProcess($AdminGroupName, "Create DomainLocal admin group in $groupsOU")) {
            try {
                New-ADGroup -Name $AdminGroupName -GroupScope DomainLocal -GroupCategory Security -Path $groupsOU -ErrorAction Stop
                $adminGroup = Get-ADGroup -Filter "Name -eq '$AdminGroupName'"
            } catch {
                Write-Log "  [X] Failed to create $AdminGroupName : $($_.Exception.Message)" -Level ERROR
                return
            }
        }
    }

    if (-not $adminGroup) {
        Write-Log "  [!] Skipping ACL changes (admin group unavailable, possibly due to -WhatIf)" -Level WARN
        return
    }

    $adminSid = New-Object System.Security.Principal.SecurityIdentifier($adminGroup.SID)

    # Resolve other tier admin SIDs for Deny entries
    $denySids = @()
    foreach ($otherName in $OtherTierAdminGroups) {
        $g = Get-ADGroup -Filter "Name -eq '$otherName'" -ErrorAction SilentlyContinue
        if ($g) {
            $denySids += [PSCustomObject]@{ Name = $otherName; Sid = (New-Object System.Security.Principal.SecurityIdentifier($g.SID)) }
        } else {
            Write-Log "  [!] Other-tier admin group not found (skipped): $otherName" -Level WARN
        }
    }

    $aclPath = "AD:$tierOU"
    $acl = Get-Acl -Path $aclPath

    # Allow FullControl for the tier admin group (inherit to descendants)
    $allRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $allowAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $adminSid,
        $allRights,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    )
    $acl.AddAccessRule($allowAce)

    # Deny WriteProperty / CreateChild / DeleteChild / WriteDacl / WriteOwner for cross-tier admin groups
    $denyRights = [System.DirectoryServices.ActiveDirectoryRights]'WriteProperty,CreateChild,DeleteChild,WriteDacl,WriteOwner'
    foreach ($entry in $denySids) {
        $denyAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $entry.Sid,
            $denyRights,
            [System.Security.AccessControl.AccessControlType]::Deny,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
        )
        $acl.AddAccessRule($denyAce)
        Write-Log "  -> Deny cross-tier writes for $($entry.Name)" -Level INFO
    }

    if ($PSCmdlet.ShouldProcess($tierOU, "Apply ACL: Allow $AdminGroupName / Deny $($OtherTierAdminGroups -join ', ')")) {
        try {
            Set-Acl -Path $aclPath -AclObject $acl -ErrorAction Stop
            Write-Log "  [OK] ACL applied to $tierOU" -Level SUCCESS
        } catch {
            Write-Log "  [X] Set-Acl failed: $($_.Exception.Message)" -Level ERROR
            throw
        }
    }
}


function New-Tier0AuthenticationPolicySilo {
    <#
    .SYNOPSIS Create or update the Tier 0 Authentication Policy and Silo from a config file.
    .DESCRIPTION
        Reads policy name, silo name, mode (Audit/Enforce), TGT lifetime, and member SamAccountNames
        from a JSON config file (Silo_config.json). Creates or updates the policy and silo, then
        performs an ADDITIVE assignment of members:
          - Accounts listed in the config but not yet assigned to the silo are added.
          - Accounts already assigned to the silo but absent from the config are NOT removed.

        The policy enforces two SDDL conditions on the resource side:
          - userAllowedToAuthenticateFrom:(@USER.ad://ext/AuthenticationSilo == "<SiloName>")
          - ComputerAllowedToAuthenticateTo:(@USER.ad://ext/AuthenticationSilo == "<SiloName>")

        Audit mode is the recommended default. Switch to Enforce only after confirming that no
        legitimate authentication is denied. The mode is read from the JSON; this function
        does not expose a -Mode parameter.

        Prerequisite (one-time, via GPO on DCs): "KDC support for claims, compound authentication
        and Kerberos armoring" set to "Always provide claims".

    .PARAMETER FunctionalLevels
        Hashtable with DomainLevel / ForestLevel produced by Test-FunctionalLevel.

    .PARAMETER SiloConfigPath
        Path to Silo_config.json.

    .EXAMPLE
        New-Tier0AuthenticationPolicySilo -FunctionalLevels $fl -SiloConfigPath .\Config\Silo_config.json
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)] [hashtable]$FunctionalLevels,
        [Parameter(Mandatory)]
        [ValidateScript({
            if (Test-Path -Path $_ -PathType Leaf) { return $true }
            throw "SiloConfigPath does not point to an existing file: '$_'"
        })]
        [string]$SiloConfigPath
    )

    # --- Load config ---
    try {
        $cfg = Get-Content -Path $SiloConfigPath -Raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Log "  [X] Failed to read $SiloConfigPath : $($_.Exception.Message)" -Level ERROR
        throw
    }

    $PolicyName         = if ($cfg.PolicyName)         { $cfg.PolicyName }         else { 'Tier0-AuthPolicy' }
    $SiloName           = if ($cfg.SiloName)           { $cfg.SiloName }           else { 'Tier0-Silo' }
    $Mode               = if ($cfg.Mode)               { $cfg.Mode }               else { 'Audit' }
    $TGTLifetimeMinutes = if ($cfg.TGTLifetimeMinutes) { [int]$cfg.TGTLifetimeMinutes } else { 45 }

    if ($Mode -notin @('Audit', 'Enforce')) {
        Write-Log "  [X] Invalid Mode '$Mode' in config (must be 'Audit' or 'Enforce')" -Level ERROR
        throw "Invalid Silo Mode: $Mode"
    }

    Write-Log "`n=== Tier 0 Authentication Policy Silo ($Mode mode) ===" -Level INFO
    Write-Log "Config file: $SiloConfigPath" -Level INFO

    if ($FunctionalLevels.DomainLevel -lt 2012) {
        Write-Log "  [!] Domain Functional Level >= 2012R2 required (current: $($FunctionalLevels.DomainLevel))" -Level WARN
        Write-Log "  [!] Skipping silo creation. Raise DFL first." -Level WARN
        return
    }

    # SDDL conditions on the resource side 
    $userAllowedToAuthenticateFrom = "O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == ""$SiloName""))"
    $computerAllowedToAuthTo = "O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == ""$SiloName""))"
    $enforce = ($Mode -eq 'Enforce')

    # ---- Policy ----
    $existingPolicy = Get-ADAuthenticationPolicy -Filter "Name -eq '$PolicyName'" -ErrorAction SilentlyContinue
    if ($existingPolicy) {
        Write-Log "  [=] Policy '$PolicyName' already exists; updating Mode and SDDL conditions" -Level INFO
        if ($PSCmdlet.ShouldProcess($PolicyName, "Set Mode=$Mode (Enforce=$enforce) and SDDL conditions")) {
            try {
                Set-ADAuthenticationPolicy -Identity $PolicyName `
                    -Enforce:$enforce `
                    -UserAllowedToAuthenticateFrom $userAllowedToAuthenticateFrom `
                    -ComputerAllowedToAuthenticateTo $computerAllowedToAuthTo `
                    -ErrorAction Stop
                Write-Log "  [OK] Policy updated: Enforce=$enforce, conditions set" -Level SUCCESS
            } catch {
                Write-Log "  [X] Failed to update policy: $($_.Exception.Message)" -Level ERROR
                throw
            }
        }
    } else {
        if ($PSCmdlet.ShouldProcess($PolicyName, "Create Authentication Policy ($Mode mode)")) {
            try {
                New-ADAuthenticationPolicy -Name $PolicyName `
                    -Description "Tier 0 access policy. Restricts inbound authentication to members of the Tier 0 silo. Managed by Sec_AD." `
                    -UserTGTLifetimeMins $TGTLifetimeMinutes `
                    -ComputerTGTLifetimeMins $TGTLifetimeMinutes `
                    -ServiceTGTLifetimeMins $TGTLifetimeMinutes `
                    -UserAllowedToAuthenticateFrom $userAllowedToAuthenticateFrom `
                    -ComputerAllowedToAuthenticateTo $computerAllowedToAuthTo `
                    -Enforce:$enforce `
                    -ErrorAction Stop
                Write-Log "  [OK] Policy created: $PolicyName (TGT lifetime: ${TGTLifetimeMinutes}m, Enforce=$enforce)" -Level SUCCESS
                Write-Log "      Condition (User -> Tier 0)  : user.AuthenticationSilo == '$SiloName'" -Level INFO
                Write-Log "      Condition (Device -> Tier 0): device.AuthenticationSilo == '$SiloName'" -Level INFO
            } catch {
                Write-Log "  [X] Failed to create policy: $($_.Exception.Message)" -Level ERROR
                throw
            }
        }
    }

    # ---- Silo ----
    $existingSilo = Get-ADAuthenticationPolicySilo -Filter "Name -eq '$SiloName'" -ErrorAction SilentlyContinue
    if ($existingSilo) {
        Write-Log "  [=] Silo '$SiloName' already exists; updating Mode" -Level INFO
        if ($PSCmdlet.ShouldProcess($SiloName, "Set Mode=$Mode (Enforce=$enforce)")) {
            try {
                Set-ADAuthenticationPolicySilo -Identity $SiloName -Enforce:$enforce -ErrorAction Stop
                Write-Log "  [OK] Silo updated: Enforce=$enforce" -Level SUCCESS
            } catch {
                Write-Log "  [X] Failed to update silo: $($_.Exception.Message)" -Level ERROR
                throw
            }
        }
    } else {
        if ($PSCmdlet.ShouldProcess($SiloName, "Create Authentication Policy Silo ($Mode mode)")) {
            try {
                New-ADAuthenticationPolicySilo -Name $SiloName `
                    -Description "Tier 0 silo. Membership defines what user.AuthenticationSilo and device.AuthenticationSilo will report. Managed by Sec_AD." `
                    -UserAuthenticationPolicy $PolicyName `
                    -ComputerAuthenticationPolicy $PolicyName `
                    -ServiceAuthenticationPolicy $PolicyName `
                    -Enforce:$enforce `
                    -ErrorAction Stop
                Write-Log "  [OK] Silo created: $SiloName (Enforce=$enforce)" -Level SUCCESS
            } catch {
                Write-Log "  [X] Failed to create silo: $($_.Exception.Message)" -Level ERROR
                throw
            }
        }
    }

    # ---- Members (additive) ----
    # Flatten Users/Computers/Services into one list. Sections are for readability only.
    $allMembers = @()
    if ($cfg.Members) {
        foreach ($section in @('Users', 'Computers', 'Services')) {
            if ($cfg.Members.PSObject.Properties.Name -contains $section) {
                $allMembers += @($cfg.Members.$section | Where-Object { $_ -and -not $_.StartsWith('_') })
            }
        }
    }
    $allMembers = $allMembers | Where-Object { $_ } | Select-Object -Unique

    Write-Log "`n-> Member assignment (additive): $($allMembers.Count) account(s) in config" -Level INFO

    if ($allMembers.Count -gt 0) {
        # Read current silo members once for idempotence check
        $currentlyAssigned = @()
        try {
            $siloDN = (Get-ADAuthenticationPolicySilo -Identity $SiloName -ErrorAction Stop).DistinguishedName
            $currentlyAssigned = @(Get-ADObject -Filter { msDS-AssignedAuthNPolicySilo -eq $siloDN } `
                                       -ErrorAction SilentlyContinue |
                                   ForEach-Object { $_.distinguishedName })
        } catch {
            Write-Log "  [!] Could not enumerate current silo members (skipping duplicate detection): $($_.Exception.Message)" -Level WARN
        }

        $silo = Get-ADAuthenticationPolicySilo -Identity $SiloName -ErrorAction SilentlyContinue
        if (-not $silo) {
            Write-Log "  [!] Silo not found post-creation (probably -WhatIf). Skipping member assignment." -Level WARN
        } else {
            foreach ($sam in $allMembers) {
                $obj = $null
                try {
                    $obj = Get-ADUser     -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue
                    if (-not $obj) {
                        $obj = Get-ADComputer -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue
                    }
                } catch { }

                if (-not $obj) {
                    Write-Log "  [X] Account not found: $sam" -Level ERROR
                    continue
                }

                if ($obj.DistinguishedName -in $currentlyAssigned) {
                    Write-Log "  [=] Already assigned: $sam" -Level INFO
                    continue
                }

                if ($PSCmdlet.ShouldProcess($sam, "Grant silo access and assign silo '$SiloName' / policy '$PolicyName'")) {
                    try {
                        Grant-ADAuthenticationPolicySiloAccess -Identity $silo -Account $obj.SamAccountName -ErrorAction Stop
                        Set-ADAccountAuthenticationPolicySilo -Identity $obj -AuthenticationPolicySilo $SiloName -ErrorAction Stop
                        Set-ADAccountAuthenticationPolicySilo -Identity $obj -AuthenticationPolicy $PolicyName -ErrorAction SilentlyContinue
                        Write-Log "  [OK] Assigned: $sam" -Level SUCCESS
                    } catch {
                        Write-Log "  [X] Failed to assign $sam : $($_.Exception.Message)" -Level ERROR
                    }
                }
            }
        }
    } else {
        Write-Log "  [!] No members declared in config. Silo created/updated but empty." -Level WARN
        Write-Log "      Add SamAccountNames to '$SiloConfigPath' under Members.Users / Computers / Services." -Level WARN
    }

    Write-Log "`n  [!] Next steps:" -Level WARN
    Write-Log "      1. Ensure 'KDC support for claims, compound authentication and Kerberos armoring'" -Level WARN
    Write-Log "         is set to 'Always provide claims' on Domain Controllers (GPO)." -Level WARN
    if ($Mode -eq 'Audit') {
        Write-Log "      2. Monitor DC events 105/305 (silo/policy), 4625, 4768, 4769, 4770." -Level WARN
        Write-Log "      3. When audit shows no unexpected denials, set Mode='Enforce' in $SiloConfigPath and re-run." -Level WARN
    } else {
        Write-Log "      [!] ENFORCE MODE ACTIVE -- authentication failures will BLOCK access." -Level WARN
        Write-Log "      To revert: set Mode='Audit' in $SiloConfigPath and re-run." -Level WARN
    }
}

function Add-Tier0SiloMember {
    <#
    .SYNOPSIS Add an account (user, computer, or service) to the Tier 0 silo.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)] [string]$Identity,
        [Parameter()]          [string]$SiloName = 'Tier0-Silo',
        [Parameter()]          [string]$PolicyName = 'Tier0-AuthPolicy'
    )

    try {
        $silo = Get-ADAuthenticationPolicySilo -Identity $SiloName -ErrorAction Stop
    } catch {
        Write-Log "  [X] Silo not found: $SiloName" -Level ERROR
        return
    }

    # Try resolving as user, then computer
    $obj = Get-ADUser -Filter "SamAccountName -eq '$Identity'" -ErrorAction SilentlyContinue
    if (-not $obj) {
        $obj = Get-ADComputer -Filter "SamAccountName -eq '$Identity'" -ErrorAction SilentlyContinue
    }
    if (-not $obj) {
        Write-Log "  [X] Identity not found as user or computer: $Identity" -Level ERROR
        return
    }

    if ($PSCmdlet.ShouldProcess($Identity, "Grant silo '$SiloName' and assign policy '$PolicyName'")) {
        try {
            Grant-ADAuthenticationPolicySiloAccess -Identity $silo -Account $obj.SamAccountName -ErrorAction Stop
            Set-ADAccountAuthenticationPolicySilo -Identity $obj -AuthenticationPolicySilo $SiloName -ErrorAction Stop
            Set-ADAccountAuthenticationPolicySilo -Identity $obj -AuthenticationPolicy $PolicyName -ErrorAction SilentlyContinue
            Write-Log "  [OK] $Identity assigned to silo $SiloName" -Level SUCCESS
        } catch {
            Write-Log "  [X] Failed to assign $Identity : $($_.Exception.Message)" -Level ERROR
            throw
        }
    }
}


function Lock-PreWindows2000Group {
    <#
    .SYNOPSIS Empty the 'Pre-Windows 2000 Compatible Access' group (S-1-5-32-554).
    .DESCRIPTION
        This built-in group historically grants read access to user/group attributes anonymously
        when 'Anonymous Logon' is a member. Removing all members (especially 'Authenticated Users'
        and 'Anonymous Logon') is a known hardening recommendation (ANSSI, MS).
        Members are exported to JSON before removal for rollback.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter()] [string]$BackupDirectory
    )

    Write-Log "`n=== Locking down 'Pre-Windows 2000 Compatible Access' ===" -Level INFO

    $sid = 'S-1-5-32-554'
    try {
        $group = Get-ADGroup -Identity $sid -Properties Members -ErrorAction Stop
    } catch {
        Write-Log "  [X] Could not resolve built-in group SID $sid : $($_.Exception.Message)" -Level ERROR
        return
    }

    $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
    if (-not $members -or $members.Count -eq 0) {
        Write-Log "  [OK] Group is already empty" -Level SUCCESS
        return
    }

    Write-Log "  Current members ($($members.Count)):" -Level INFO
    foreach ($m in $members) {
        Write-Log "    - $($m.SamAccountName) ($($m.objectClass))" -Level INFO
    }

    # Backup
    if ($BackupDirectory) {
        if (-not (Test-Path $BackupDirectory)) {
            New-Item -ItemType Directory -Path $BackupDirectory -Force -WhatIf:$false -Confirm:$false | Out-Null
        }
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $backupFile = Join-Path $BackupDirectory "preWin2000_members_${timestamp}.json"
        $members | Select-Object SamAccountName, distinguishedName, SID, objectClass |
            ConvertTo-Json -Depth 5 | Set-Content -Path $backupFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
        Write-Log "  [OK] Membership backup: $backupFile" -Level SUCCESS
    }

    foreach ($m in $members) {
        if ($PSCmdlet.ShouldProcess($m.SamAccountName, "Remove from Pre-Windows 2000 Compatible Access")) {
            try {
                Remove-ADGroupMember -Identity $group -Members $m -Confirm:$false -ErrorAction Stop
                Write-Log "    [OK] Removed: $($m.SamAccountName)" -Level SUCCESS
            } catch {
                Write-Log "    [X] Failed to remove $($m.SamAccountName): $($_.Exception.Message)" -Level ERROR
            }
        }
    }
}


function Get-PrivilegedGroupAudit {
    <#
    .SYNOPSIS List members of Domain Admins / Enterprise Admins / Schema Admins.
    .DESCRIPTION
        Read-only audit. Recommends review/removal for any human account that isn't
        an emergency-use ('break-glass') account. Returns a structured report.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [string[]]$GroupNames = @('Domain Admins', 'Enterprise Admins', 'Schema Admins'),
        [Parameter()] [string]$ReportPath
    )

    Write-Log "`n=== Privileged Group Audit ===" -Level INFO
    $report = [System.Collections.Generic.List[object]]::new()

    foreach ($groupName in $GroupNames) {
        try {
            $group = Get-ADGroup -Identity $groupName -ErrorAction Stop
            $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue
        } catch {
            Write-Log "  [!] Group not found or unreadable: $groupName" -Level WARN
            continue
        }

        Write-Log "`n  [$groupName] $($members.Count) member(s)" -Level INFO
        foreach ($m in $members) {
            $userObj = $null
            try {
                if ($m.objectClass -eq 'user') {
                    $userObj = Get-ADUser -Identity $m -Properties LastLogonDate, PasswordLastSet, Enabled, Description -ErrorAction Stop
                }
            } catch { }

            $entry = [PSCustomObject]@{
                Group           = $groupName
                Member          = $m.SamAccountName
                ObjectClass     = $m.objectClass
                DistinguishedName = $m.distinguishedName
                Enabled         = if ($userObj) { $userObj.Enabled } else { $null }
                LastLogonDate   = if ($userObj) { $userObj.LastLogonDate } else { $null }
                PasswordLastSet = if ($userObj) { $userObj.PasswordLastSet } else { $null }
                Description     = if ($userObj) { $userObj.Description } else { $null }
                Recommendation  = ''
            }

            # Heuristic recommendations
            $recos = @()
            if ($m.SamAccountName -eq 'Administrator') {
                $recos += 'Built-in Administrator: keep as break-glass (offline credentials, MFA, monitored).'
            } elseif ($m.objectClass -eq 'user') {
                $recos += 'Review: human accounts should not be permanent members; use just-in-time elevation.'
            } elseif ($m.objectClass -eq 'group') {
                $recos += 'Nested group: enumerate recursively; flat membership is preferred for privileged groups.'
            }
            $entry.Recommendation = $recos -join ' '

            $report.Add($entry)
            Write-Log "    - $($entry.Member) ($($entry.ObjectClass), enabled=$($entry.Enabled))" -Level INFO
            if ($entry.Recommendation) {
                Write-Log "      => $($entry.Recommendation)" -Level WARN
            }
        }
    }

    if ($ReportPath) {
        $report | ConvertTo-Json -Depth 5 | Set-Content -Path $ReportPath -Encoding UTF8 -WhatIf:$false -Confirm:$false
        Write-Log "`n  [OK] Report saved: $ReportPath" -Level SUCCESS
    }

    return $report
}

function Remove-PrivilegedGroupMember {
    <#
    .SYNOPSIS Remove a member from a privileged group, with safety checks.
    .DESCRIPTION
        Refuses to remove the built-in Administrator account by default (-AllowAdministratorRemoval to override).
        Always runs through ShouldProcess; combined with -Confirm:$true (default for High impact).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [string]$GroupName,
        [Parameter(Mandatory)] [string]$MemberSamAccountName,
        [Parameter()] [switch]$AllowAdministratorRemoval
    )

    if ($MemberSamAccountName -eq 'Administrator' -and -not $AllowAdministratorRemoval) {
        Write-Log "  [X] Refusing to remove built-in 'Administrator' (use -AllowAdministratorRemoval to override)" -Level ERROR
        return
    }

    try {
        $group = Get-ADGroup -Identity $GroupName -ErrorAction Stop
    } catch {
        Write-Log "  [X] Group not found: $GroupName" -Level ERROR
        return
    }

    if ($PSCmdlet.ShouldProcess("$MemberSamAccountName from $GroupName", 'Remove privileged group membership')) {
        try {
            Remove-ADGroupMember -Identity $group -Members $MemberSamAccountName -Confirm:$false -ErrorAction Stop
            Write-Log "  [OK] Removed $MemberSamAccountName from $GroupName" -Level SUCCESS
        } catch {
            Write-Log "  [X] Failed: $($_.Exception.Message)" -Level ERROR
            throw
        }
    }
}


function Set-Tier0AccountSensitive {
    <#
    .SYNOPSIS Mark Tier 0 user accounts as 'Account is sensitive and cannot be delegated'.
    .DESCRIPTION
        Sets the AccountNotDelegated flag on user accounts found in the _Tier0\Admins OU.
        This prevents the account's TGT from being forwarded to services for delegation,
        a key control against credential theft via Kerberos delegation abuse.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)] [string]$RootDN,
        [Parameter()] [string]$Tier0AdminsOU
    )

    Write-Log "`n=== Setting AccountNotDelegated on Tier 0 admin accounts ===" -Level INFO

    if (-not $Tier0AdminsOU) {
        $Tier0AdminsOU = "OU=Admins,OU=_Tier0,$RootDN"
    }

    try {
        Get-ADOrganizationalUnit -Identity $Tier0AdminsOU -ErrorAction Stop | Out-Null
    } catch {
        Write-Log "  [X] Tier 0 Admins OU not found: $Tier0AdminsOU" -Level ERROR
        return
    }

    $users = Get-ADUser -SearchBase $Tier0AdminsOU -Filter * -Properties AccountNotDelegated, Enabled
    if (-not $users) {
        Write-Log "  [!] No user accounts in $Tier0AdminsOU" -Level WARN
        return
    }

    foreach ($u in $users) {
        if ($u.AccountNotDelegated) {
            Write-Log "  [OK] $($u.SamAccountName): already sensitive" -Level SUCCESS
            continue
        }
        if ($PSCmdlet.ShouldProcess($u.SamAccountName, 'Set AccountNotDelegated = $true')) {
            try {
                Set-ADUser -Identity $u -AccountNotDelegated $true -ErrorAction Stop
                Write-Log "  [OK] $($u.SamAccountName): marked sensitive (cannot be delegated)" -Level SUCCESS
            } catch {
                Write-Log "  [X] $($u.SamAccountName): $($_.Exception.Message)" -Level ERROR
            }
        }
    }
}

Export-ModuleMember -Function `
    Set-ADSIUnauthenticatedBind, Set-msDSMachineAccountQuota, `
    Set-KerberosEncryptionTypes, Enable-RecycleBin, Enable-LAPS, Enable-Bitlocker, `
    Set-TierOUDelegation, Backup-OUSecurityDescriptor, `
    New-Tier0AuthenticationPolicySilo, Add-Tier0SiloMember, `
    Lock-PreWindows2000Group, `
    Get-PrivilegedGroupAudit, Remove-PrivilegedGroupMember, `
    Set-Tier0AccountSensitive
