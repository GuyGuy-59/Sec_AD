function Set-ADSIUnauthenticatedBind {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetDomain
    )
    
    try {
        Write-Host "`n=== Configuring ADSI Unauthenticated Bind ===" -ForegroundColor Cyan
        Write-Host "Target Domain: $TargetDomain" -ForegroundColor Yellow
        
        Write-Host "`n-> Building Directory Service DN..." -ForegroundColor Yellow
        $domainDN = "DC=" + ($TargetDomain -replace "\.", ",DC=")
        $directoryServiceDn = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$domainDN"
        
        Write-Host "-> Retrieving Directory Service object..." -ForegroundColor Yellow
        $directoryService = Get-ADObject -Identity $directoryServiceDn -Properties "msDS-Other-Settings"
        
        Write-Host "`nCurrent Configuration:" -ForegroundColor Yellow
        Write-Host "  msDS-Other-Settings: $($directoryService."msDS-Other-Settings")" -ForegroundColor Gray
        
        $currentValue = $directoryService."msDS-Other-Settings"
        
        if ($currentValue -notcontains "DenyUnauthenticatedBind=1") {
            if ([string]::IsNullOrEmpty($currentValue)) {
                $newValue = @("DenyUnauthenticatedBind=1")
            } else {
                $newValue = $currentValue + "DenyUnauthenticatedBind=1"
            }
            
            Set-ADObject -Identity $directoryServiceDn -Replace @{ "msDS-Other-Settings" = $newValue }
            Write-Host "[OK] Successfully configured DenyUnauthenticatedBind=1" -ForegroundColor Green
        } else {
            Write-Host "[OK] DenyUnauthenticatedBind=1 is already configured" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "[X] Configuration failed: $_"
        throw
    }
}

function Set-msDSMachineAccountQuota {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetDomain
    )
    
    try {
        Write-Host "`n=== Configuring ms-DS-MachineAccountQuota ===" -ForegroundColor Cyan
        Write-Host "Target Domain: $TargetDomain" -ForegroundColor Yellow
        
        Write-Host "`n-> Building domain DN..." -ForegroundColor Yellow
        $domainDN = "DC=" + ($TargetDomain -replace '\.', ',DC=')
        
        Write-Host "-> Retrieving current ms-DS-MachineAccountQuota value..." -ForegroundColor Yellow
        $currentQuota = (Get-ADObject -Identity $domainDN -Properties "ms-DS-MachineAccountQuota")."ms-DS-MachineAccountQuota"
        
        Write-Host "Current ms-DS-MachineAccountQuota value: $currentQuota" -ForegroundColor Yellow
        
        # Check if update is needed (should be 0 for security)
        if ($currentQuota -ne 0) {
            Write-Host "[!] Updating ms-DS-MachineAccountQuota to 0..." -ForegroundColor Yellow
            
            # Set ms-DS-MachineAccountQuota to 0
            Set-ADObject -Identity $domainDN -Replace @{ "ms-DS-MachineAccountQuota" = 0 }
            
            Write-Host "[OK] Successfully set ms-DS-MachineAccountQuota to 0" -ForegroundColor Green
        } else {
            Write-Host "[OK] ms-DS-MachineAccountQuota is already set to 0" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "[X] Configuration failed: $_"
        throw
    }
}

function Enable-RecycleBin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$TargetDomain,

        [Parameter(Mandatory=$true)]
        [hashtable]$FunctionalLevels

    )
    Write-Host "`n=== Configuring AD Recycle Bin ===" -ForegroundColor Cyan
    
    try {
        Write-Host "-> Checking forest functional level..." -ForegroundColor Yellow
        Write-Host "  Current level: $($FunctionalLevels.ForestLevel)" -ForegroundColor Gray
        if ($FunctionalLevels.ForestLevel -lt 2008) {
            Write-Host "[X] Forest functional level is not sufficient (minimum: Windows Server 2008 R2)." -ForegroundColor Red
            Write-Host "[!] Please raise the forest functional level before enabling the Recycle Bin."
            exit
        }

        # Check if Recycle Bin feature is enabled
        $recycleBinFeature = Get-ADOptionalFeature -Filter {Name -eq 'Recycle Bin Feature'}

        if ($recycleBinFeature.EnabledScopes) {
            Write-Host "[OK] Active Directory Recycle Bin is already enabled." -ForegroundColor Green
        } else {
            Write-Host "[!] Enabling Active Directory Recycle Bin..." -ForegroundColor Yellow

            # Enable Recycle Bin
            try {
                Enable-ADOptionalFeature -Identity $recycleBinFeature -Scope ForestOrConfigurationSet -Target $TargetDomain -Confirm:$false
                Write-Host "[OK] Active Directory Recycle Bin has been successfully enabled." -ForegroundColor Green
            } catch {
                Write-Host "[X] An error occurred while enabling the Recycle Bin: $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        # Final state confirmation
        Write-Host "-> Performing final check of Recycle Bin status..." -ForegroundColor Cyan
        $recycleBinFeature = Get-ADOptionalFeature -Filter {Name -eq 'Recycle Bin Feature'}
        if ($recycleBinFeature.EnabledScopes) {
            Write-Host "[OK] Active Directory Recycle Bin is enabled." -ForegroundColor Green
        } else {
            Write-Host "[X] Active Directory Recycle Bin could not be enabled." -ForegroundColor Red
        }
    }
    catch {
        Write-Error "[X] Recycle Bin configuration failed: $_"
        throw
    }
}

function Enable-LAPS {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetDomain
    )

    try {
        Write-Host "`n=== Configuring LAPS ===" -ForegroundColor Cyan
        Write-Host "Target Domain: $TargetDomain" -ForegroundColor Yellow
        
        # Check if LAPS is present  
        $lapsFeature = Get-Command -Module LAPS
        if ($lapsFeature) {
            Update-LapsADSchema -Verbose -Confirm:$false
            Write-Host "[!] Updating LAPS AD Schema..." -ForegroundColor Yellow
            
            $domainDN = (Get-ADDomain $TargetDomain).DistinguishedName
            $workstationsOU = "OU=Workstations,OU=_Tier2,$domainDN"
            
            Set-LapsADComputerSelfPermission -Identity $workstationsOU
            Write-Host "[OK] Setting LAPS AD Computer Self Permission..." -ForegroundColor Yellow
            
            Set-LapsADReadPasswordPermission -Identity $workstationsOU -AllowedPrincipals "$TargetDomain\LAPS-Pwd-Read"
            Write-Host "[OK] Setting LAPS password read permissions..." -ForegroundColor Yellow

            Write-Host "`n[!] IMPORTANT:" -ForegroundColor Yellow
            Write-Host "The LAPS-Enabled GPO must be modified to add $TargetDomain\LAPS-Pwd-Read" -ForegroundColor Yellow
            Write-Host "in the 'Configure authorized password decryptors' setting" -ForegroundColor Yellow
        } else {
            Write-Host "[X] LAPS is not installed." -ForegroundColor Red
        }
    }catch {
        Write-Error "[X] LAPS configuration failed: $_"
        throw
    }
}
  
function Set-KerberosEncryptionTypes {
    try {
        Write-Host "`n=== Setting msDS-SupportedEncryptionTypes for krbtgt and Domain Controllers ===" -ForegroundColor Cyan

        $encryptionTypes = @{
            0x1 = "DES_CBC_CRC"
            0x2 = "DES_CBC_MD5"
            0x4 = "RC4"
            0x8 = "AES 128"
            0x10 = "AES 256"
        }
        $newEncryptionTypes = 0x18

        # Function to display and update encryption types
        function Update-EncryptionTypes {
            param(
                [Parameter(Mandatory=$true)]
                [Microsoft.ActiveDirectory.Management.ADObject]$Account,
                
                [Parameter(Mandatory=$true)]
                [string]$AccountName
            )
            
            $currentEncryptionTypes = if ($null -eq $Account."msDS-SupportedEncryptionTypes") { 0 } else { $Account."msDS-SupportedEncryptionTypes" }
            
            # Display current encryption types
            Write-Host "`n-> $AccountName" -ForegroundColor Yellow
            Write-Host "  Current Encryption Types (Decimal: $currentEncryptionTypes, Hex: 0x$($currentEncryptionTypes.ToString('X')))" -ForegroundColor Gray
            Write-Host "  Supported Encryption Types:" -ForegroundColor Gray
            
            $supportedTypes = @()
            foreach ($type in $encryptionTypes.GetEnumerator()) {
                if ($currentEncryptionTypes -band $type.Key) {
                    $supportedTypes += $type.Value
                }
            }
            
            if ($supportedTypes.Count -eq 0) {
                Write-Host "    Not defined - defaults to RC4_HMAC_MD5" -ForegroundColor Gray
            } else {
                $supportedTypes | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
            }

            # Update if needed
            if ($currentEncryptionTypes -ne $newEncryptionTypes) {
                Set-ADObject -Identity $Account -Replace @{"msDS-SupportedEncryptionTypes" = $newEncryptionTypes}
                
                if ($?) {
                    $updatedAccount = Get-ADObject -Identity $Account -Property msDS-SupportedEncryptionTypes
                    $newValue = $updatedAccount."msDS-SupportedEncryptionTypes"
                    Write-Host "  [OK] msDS-SupportedEncryptionTypes updated to:" -ForegroundColor Green
                    Write-Host "    Decimal: $newValue" -ForegroundColor Gray
                    Write-Host "    Hex: 0x$($newValue.ToString('X'))" -ForegroundColor Gray
                    Write-Host "    Supported Types:" -ForegroundColor Gray
                    $supportedTypes = @()
                    foreach ($type in $encryptionTypes.GetEnumerator()) {
                        if ($newValue -band $type.Key) {
                            $supportedTypes += $type.Value
                        }
                    }
                    $supportedTypes | ForEach-Object {
                        Write-Host "      $_" -ForegroundColor Gray
                    }
                } else {
                    Write-Host "  [X] Failed to update msDS-SupportedEncryptionTypes." -ForegroundColor Red
                }
            } else {
                Write-Host "  [OK] Encryption types already configured correctly" -ForegroundColor Green
            }
        }

        # Configure krbtgt account
        Write-Host "`n=== Configuring krbtgt account ===" -ForegroundColor Cyan
        $krbtgtAccount = Get-ADObject -Filter {Name -eq "krbtgt"} -Property msDS-SupportedEncryptionTypes
        if ($krbtgtAccount) {
            Update-EncryptionTypes -Account $krbtgtAccount -AccountName "krbtgt"
        } else {
            Write-Host "[X] krbtgt account not found." -ForegroundColor Red
        }

        # Configure Domain Controllers
        Write-Host "`n=== Configuring Domain Controllers ===" -ForegroundColor Cyan
        $domainControllers = Get-ADComputer -Filter {PrimaryGroupID -eq 516} -Property msDS-SupportedEncryptionTypes
        
        if ($domainControllers) {
            Write-Host "Found $($domainControllers.Count) Domain Controller(s)" -ForegroundColor Yellow
            foreach ($dc in $domainControllers) {
                Update-EncryptionTypes -Account $dc -AccountName $dc.Name
            }
        } else {
            Write-Host "[!] No Domain Controllers found." -ForegroundColor Yellow
        }

    } catch {
        Write-Error "[X] Failed to set msDS-SupportedEncryptionTypes: $_"
        throw
    }
}

function Enable-Bitlocker {
    [CmdletBinding()]
    param()

    try {
        Write-Host "`n=== Installing BitLocker RSAT Features ===" -ForegroundColor Cyan
        
        $requiredFeatures = @(
            "RSAT-Feature-Tools-BitLocker",
            "RSAT-Feature-Tools-BitLocker-RemoteAdminTool", 
            "RSAT-Feature-Tools-BitLocker-BdeAducExt"
        )
        
        Write-Host "-> Checking and installing BitLocker RSAT features..." -ForegroundColor Yellow
        
        foreach ($feature in $requiredFeatures) {
            $installed = Get-WindowsFeature -Name $feature -ErrorAction SilentlyContinue
            if (-not $installed -or $installed.InstallState -ne "Installed") {
                Write-Host "  Installing: $feature" -ForegroundColor Gray
                Install-WindowsFeature -Name $feature -IncludeAllSubFeature -IncludeManagementTools
                Write-Host "  [OK] $feature installed successfully" -ForegroundColor Green
            } else {
                Write-Host "  [OK] $feature is already installed" -ForegroundColor Green
            }
        }
        
        Write-Host "`n[OK] All BitLocker RSAT features are now installed!" -ForegroundColor Green
        
    } catch {
        Write-Error "[X] Failed to install BitLocker RSAT features: $_"
        throw
    }
}

# Export all functions
Export-ModuleMember -Function Set-ADSIUnauthenticatedBind, Set-msDSMachineAccountQuota, Set-KerberosEncryptionTypes, Enable-RecycleBin, Enable-LAPS, Enable-Bitlocker