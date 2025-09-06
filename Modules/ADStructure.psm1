function Initialize-ADStructure {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$RootDN,
        
        [Parameter(Mandatory=$true)]
        [string]$AdmName,
        
        [Parameter(Mandatory=$true)]
        [string[]]$TierNames,
        
        [Parameter(Mandatory=$true)]
        [string[]]$SubOUs,
        
        [Parameter(Mandatory=$true)]
        [string[]]$Tier0and1SubOUs,
        
        [Parameter(Mandatory=$true)]
        [string]$DisabledOU
    )
    
    try {
        Write-Host "`n=== Creating ADM Structure ===" -ForegroundColor Cyan
        Write-Host "Creating base ADM structure in: $RootDN" -ForegroundColor Yellow
        $AdmDN = New-OU -ParentDN $RootDN -OUName "_$AdmName"
        
        Write-Host "`n-> Creating ADM Tiers..." -ForegroundColor Yellow
        foreach ($TierName in $TierNames) {
            New-OU -ParentDN $AdmDN -OUName $TierName
        }

        Write-Host "`n=== Creating Tier Structure ===" -ForegroundColor Cyan
        Write-Host "Creating base Tier OUs..." -ForegroundColor Yellow
        $TierDNs = @{}
        foreach ($TierName in $TierNames) {
            $TierDNs[$TierName] = New-OU -ParentDN $RootDN -OUName "_$TierName"
        }

        Write-Host "`n=== Creating Sub-OUs ===" -ForegroundColor Cyan
        foreach ($TierName in $TierNames) {
            Write-Host "`n-> Processing $TierName..." -ForegroundColor Yellow
            $TierDN = $TierDNs[$TierName]
            
            if ($TierName -match "Tier0") {
                Write-Host "  -> Creating Tier0 special OUs..." -ForegroundColor Yellow
                foreach ($SpecialOU in @("PAW")) {
                    $SpecialDN = New-OU -ParentDN $TierDN -OUName $SpecialOU
                    New-OU -ParentDN $SpecialDN -OUName $DisabledOU
                }
            }    
            if ($TierName -match "Tier2") {
                Write-Host "  -> Creating Tier2 structure..." -ForegroundColor Yellow
                foreach ($SubOU in $SubOUs) {
                    $SubOUDN = New-OU -ParentDN $TierDN -OUName $SubOU
                    New-OU -ParentDN $SubOUDN -OUName $DisabledOU
                }
                
                Write-Host "  -> Creating Tier2 special OUs..." -ForegroundColor Yellow
                foreach ($SpecialOU in @("Users", "Workstations")) {
                    $SpecialDN = New-OU -ParentDN $TierDN -OUName $SpecialOU
                    New-OU -ParentDN $SpecialDN -OUName $DisabledOU
                }
            } 
            else {
                Write-Host "  -> Creating Tier0/1 structure..." -ForegroundColor Yellow
                foreach ($SubOU in $Tier0and1SubOUs) {
                    $SubOUDN = New-OU -ParentDN $TierDN -OUName $SubOU
                    New-OU -ParentDN $SubOUDN -OUName $DisabledOU
                }
            }

            Write-Host "  -> Creating security groups..." -ForegroundColor Yellow
            $GroupsOU = "OU=Groups,$($TierDNs[$TierName])"
            New-Group -GroupName "${TierName}_Users" -GroupScope "Global" -ParentOU $GroupsOU
            
            Write-Host "  -> Creating LAPS-Pwd-Read group..." -ForegroundColor Yellow
            if ($TierName -match "Tier2") {
                Write-Host "  -> Creating LAPS-Pwd-Read group in ADM Tier2..." -ForegroundColor Yellow
                $admTier2GroupsOU = "OU=Tier2,OU=_$AdmName,$RootDN"
                New-Group -GroupName "LAPS-Pwd-Read" -GroupScope "DomainLocal" -ParentOU $admTier2GroupsOU
            }

            Write-Host "  -> Creating PAW local groups..." -ForegroundColor Yellow
            $pawGroupsOU = "OU=$TierName,OU=_$AdmName,$RootDN"
            New-Group -GroupName "PAW-${TierName}" -GroupScope "DomainLocal" -ParentOU $pawGroupsOU


            # Add specific groups to Protected Users group
            <# if ($TierName -match "Tier[01]") {
                $protectedUsersGroup = Get-ADGroup "Protected Users"
                if ($TierName -eq "Tier1") {
                    Add-ADGroupMember -Identity $protectedUsersGroup -Members "T1_Users","T1_Users_legacy"
                } elseif ($TierName -eq "Tier0") {
                    Add-ADGroupMember -Identity $protectedUsersGroup -Members "T0_Users"
                }
            } #>
        }

        Write-Host "`n[OK] Active Directory structure completed successfully!" -ForegroundColor Green
    }
    catch {
        Write-Error "[X] Failed to initialize AD structure: $_"
        throw
    }
}

# Export all functions
Export-ModuleMember -Function Initialize-ADStructure 