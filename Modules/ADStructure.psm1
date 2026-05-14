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
        [Parameter(Mandatory)] [string]$RootDN,
        [Parameter(Mandatory)] [string]$AdmName,
        [Parameter(Mandatory)] [string[]]$TierNames,
        [Parameter(Mandatory)] [string[]]$SubOUs,
        [Parameter(Mandatory)] [string[]]$Tier0and1SubOUs,
        [Parameter(Mandatory)] [string]$DisabledOU
    )

    try {
        # 1. ADM root + one admin sub-OU per tier
        Write-Log "`n=== Creating ADM Structure ===" -Level INFO -Color Cyan
        $AdmDN = New-OU -ParentDN $RootDN -OUName "_$AdmName"
        foreach ($TierName in $TierNames) {
            New-OU -ParentDN $AdmDN -OUName $TierName | Out-Null
        }

        # 2. Tier root OUs
        Write-Log "`n=== Creating Tier Root OUs ===" -Level INFO -Color Cyan
        $TierDNs = @{}
        foreach ($TierName in $TierNames) {
            $TierDNs[$TierName] = New-OU -ParentDN $RootDN -OUName "_$TierName"
        }

        # 3. Sub-OUs and security groups per tier
        Write-Log "`n=== Creating Sub-OUs and Groups ===" -Level INFO -Color Cyan
        foreach ($TierName in $TierNames) {
            Write-Log "`n-> Processing $TierName..." -Level INFO
            $TierDN    = $TierDNs[$TierName]
            $admTierOU = "OU=$TierName,OU=_$AdmName,$RootDN"

            # Tier0: PAW container
            if ($TierName -eq 'Tier0') {
                $pawDN = New-OU -ParentDN $TierDN -OUName 'PAW'
                New-OU -ParentDN $pawDN -OUName $DisabledOU | Out-Null
            }

            # Sub-OUs (each gets a Disabled child)
            $subList = if ($TierName -eq 'Tier2') { $SubOUs } else { $Tier0and1SubOUs }
            foreach ($sub in $subList) {
                $subDN = New-OU -ParentDN $TierDN -OUName $sub
                New-OU -ParentDN $subDN -OUName $DisabledOU | Out-Null
            }

            # Tier2: flat Users and Workstations containers
            if ($TierName -eq 'Tier2') {
                foreach ($container in @('Users', 'Workstations')) {
                    $contDN = New-OU -ParentDN $TierDN -OUName $container
                    New-OU -ParentDN $contDN -OUName $DisabledOU | Out-Null
                }
            }

            # Tier-level user group (in Groups OU already created above via $subList)
            $GroupsOU = "OU=Groups,$TierDN"
            New-Group -GroupName "${TierName}_Users" -GroupScope 'Global' -ParentOU $GroupsOU

            # ADM-side groups specific to each tier
            switch ($TierName) {
                'Tier0' {
                    New-Group -GroupName 'PAW-Tier0'        -GroupScope 'DomainLocal' -ParentOU $admTierOU
                    New-Group -GroupName 'LAPS-Pwd-Read-T0' -GroupScope 'DomainLocal' -ParentOU $admTierOU
                }
                'Tier1' {
                    New-Group -GroupName 'PAW-Tier1'        -GroupScope 'DomainLocal' -ParentOU $admTierOU
                }
                'Tier2' {
                    New-Group -GroupName 'LAPS-Pwd-Read-T2' -GroupScope 'DomainLocal' -ParentOU $admTierOU
                }
            }
        }

        Write-Log "`n[OK] Active Directory structure completed successfully!" -Level SUCCESS
    } catch {
        Write-Error "[X] Failed to initialize AD structure: $_"
        throw
    }
}

Export-ModuleMember -Function Initialize-ADStructure
