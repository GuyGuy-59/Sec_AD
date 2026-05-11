<#
.SYNOPSIS
    Initializes the tiered OU and group structure required by Sec_AD.

.DESCRIPTION
    Creates the complete organizational unit hierarchy (ADM admin tier OUs, tier root OUs,
    sub-OUs, and PAW containers) and the associated security groups used for tier isolation.
    The operation is idempotent: existing OUs and groups are left untouched.

    New-OU and New-Group are private helpers (not exported) used only by Initialize-ADStructure.

    Functions exported:
      - Initialize-ADStructure : build the full ADM + tier OU tree and create baseline security groups
#>

function New-OU {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory=$true)] [string]$ParentDN,
        [Parameter(Mandatory=$true)] [string]$OUName
    )

    $OUPath = "OU=$OUName,$ParentDN"

    try {
        Write-Log "`n-> Creating OU: $OUName" -Level INFO
        Write-Log "  Parent DN: $ParentDN" -Level DEBUG

        $existing = Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -SearchBase $ParentDN -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Log "  [OK] OU already exists" -Level INFO
            return $OUPath
        }

        if ($PSCmdlet.ShouldProcess($OUPath, 'Create OU')) {
            New-ADOrganizationalUnit -Name $OUName -Path $ParentDN -ErrorAction Stop
            Write-Log "  [OK] OU created successfully" -Level SUCCESS
        }
        return $OUPath
    } catch {
        Write-Log "[X] Failed to create OU '${OUName}': $_" -Level ERROR
        throw
    }
}

function New-Group {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory=$true)] [string]$GroupName,
        [Parameter(Mandatory=$true)]
        [ValidateSet("DomainLocal", "Global", "Universal")]
        [string]$GroupScope,
        [Parameter(Mandatory=$true)] [string]$ParentOU
    )

    try {
        Write-Log "`n-> Creating Group: $GroupName" -Level INFO
        Write-Log "  Parent OU: $ParentOU" -Level DEBUG

        $existing = Get-ADGroup -Filter "Name -eq '$GroupName'" -SearchBase $ParentOU -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Log "  [OK] Group already exists" -Level INFO
            return
        }

        if ($PSCmdlet.ShouldProcess($GroupName, "Create $GroupScope group in $ParentOU")) {
            New-ADGroup -Name $GroupName -GroupScope $GroupScope -Path $ParentOU -GroupCategory Security -ErrorAction Stop
            Write-Log "  [OK] Group created successfully" -Level SUCCESS
        }
    } catch {
        Write-Log "[X] Failed to create group '${GroupName}': $_" -Level ERROR
        throw
    }
}

function Initialize-ADStructure {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory=$true)] [string]$RootDN,
        [Parameter(Mandatory=$true)] [string]$AdmName,
        [Parameter(Mandatory=$true)] [string[]]$TierNames,
        [Parameter(Mandatory=$true)] [string[]]$SubOUs,
        [Parameter(Mandatory=$true)] [string[]]$Tier0and1SubOUs,
        [Parameter(Mandatory=$true)] [string]$DisabledOU
    )

    try {
        Write-Log "`n=== Creating ADM Structure ===" -Level INFO -Color Cyan
        Write-Log "Creating base ADM structure in: $RootDN" -Level INFO
        $AdmDN = New-OU -ParentDN $RootDN -OUName "_$AdmName"

        Write-Log "`n-> Creating ADM Tiers..." -Level INFO
        foreach ($TierName in $TierNames) {
            New-OU -ParentDN $AdmDN -OUName $TierName
        }

        Write-Log "`n=== Creating Tier Structure ===" -Level INFO -Color Cyan
        Write-Log "Creating base Tier OUs..." -Level INFO
        $TierDNs = @{}
        foreach ($TierName in $TierNames) {
            $TierDNs[$TierName] = New-OU -ParentDN $RootDN -OUName "_$TierName"
        }

        Write-Log "`n=== Creating Sub-OUs ===" -Level INFO -Color Cyan
        foreach ($TierName in $TierNames) {
            Write-Log "`n-> Processing $TierName..." -Level INFO
            $TierDN = $TierDNs[$TierName]

            if ($TierName -match "Tier0") {
                Write-Log "  -> Creating Tier0 special OUs..." -Level INFO
                foreach ($SpecialOU in @("PAW")) {
                    $SpecialDN = New-OU -ParentDN $TierDN -OUName $SpecialOU
                    New-OU -ParentDN $SpecialDN -OUName $DisabledOU
                }
            }
            if ($TierName -match "Tier2") {
                Write-Log "  -> Creating Tier2 structure..." -Level INFO
                foreach ($SubOU in $SubOUs) {
                    $SubOUDN = New-OU -ParentDN $TierDN -OUName $SubOU
                    New-OU -ParentDN $SubOUDN -OUName $DisabledOU
                }

                Write-Log "  -> Creating Tier2 special OUs..." -Level INFO
                foreach ($SpecialOU in @("Users", "Workstations")) {
                    $SpecialDN = New-OU -ParentDN $TierDN -OUName $SpecialOU
                    New-OU -ParentDN $SpecialDN -OUName $DisabledOU
                }
            } else {
                Write-Log "  -> Creating Tier0/1 structure..." -Level INFO
                foreach ($SubOU in $Tier0and1SubOUs) {
                    $SubOUDN = New-OU -ParentDN $TierDN -OUName $SubOU
                    New-OU -ParentDN $SubOUDN -OUName $DisabledOU
                }
            }

            Write-Log "  -> Creating security groups..." -Level INFO
            $GroupsOU = "OU=Groups,$($TierDNs[$TierName])"
            New-Group -GroupName "${TierName}_Users" -GroupScope "Global" -ParentOU $GroupsOU

            if ($TierName -eq "Tier2") {
                Write-Log "  -> Creating LAPS-Pwd-Read group in ADM Tier2..." -Level INFO
                $admTier2GroupsOU = "OU=Tier2,OU=_$AdmName,$RootDN"
                New-Group -GroupName "LAPS-Pwd-Read" -GroupScope "DomainLocal" -ParentOU $admTier2GroupsOU
            }

            if ($TierName -eq "Tier0" -or $TierName -eq "Tier1") {
                Write-Log "  -> Creating PAW-${TierName} local group..." -Level INFO
                $pawGroupsOU = "OU=$TierName,OU=_$AdmName,$RootDN"
                New-Group -GroupName "PAW-${TierName}" -GroupScope "DomainLocal" -ParentOU $pawGroupsOU
            }
        }

        Write-Log "`n[OK] Active Directory structure completed successfully!" -Level SUCCESS
    } catch {
        Write-Error "[X] Failed to initialize AD structure: $_"
        throw
    }
}

Export-ModuleMember -Function Initialize-ADStructure
