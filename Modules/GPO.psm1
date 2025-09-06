function Get-GPOsToImport {
    param (
        [hashtable]$FunctionalLevels,
        [object]$GPOConfig
    )
    $gposToImport = $GPOConfig.GPOs.Common.gpos
    if ($FunctionalLevels.ForestLevel -ge 2025) {
        $gposToImport += $GPOConfig.GPOs.Level2025.gpos
    } elseif ($FunctionalLevels.ForestLevel -le 2016) {
        $gposToImport += $GPOConfig.GPOs.Level2016.gpos
    }
    return $gposToImport
}

function Import-SecurityHardeningGPOs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$BackupPath,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetDomain,

        [Parameter(Mandatory=$true)]
        [hashtable]$FunctionalLevels,

        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$gpoConfigPath

    )
    
    try {
        Write-Host "`n=== Importing Security Hardening GPOs ===" -ForegroundColor Cyan
        $script:gpoConfig = Get-Content -Path $gpoConfigPath -Raw | ConvertFrom-Json
        $gposToImport = Get-GPOsToImport -FunctionalLevels $FunctionalLevels -GPOConfig $script:gpoConfig
        $absoluteBackupPath = (Resolve-Path $BackupPath).Path
        Write-Host "Source path: $absoluteBackupPath" -ForegroundColor Yellow
        
        Write-Host "`n-> Scanning for GPO backups..." -ForegroundColor Yellow
        $gpoBackups = Get-ChildItem -Path $absoluteBackupPath -Directory
        Write-Host "  Found $($gpoBackups.Count) backup folders" -ForegroundColor Gray
        Write-Host "  Total GPOs to import: $($gposToImport.Count) " -ForegroundColor Gray
        
        if ($gpoBackups.Count -eq 0) {
            Write-Error "[X] No GPO backup folders found in: $absoluteBackupPath"
            Write-Error "[X] Please ensure the GPO backup files are present in the specified directory"
            return
        }
        
        foreach ($backup in $gpoBackups) {
            Write-Host "`n-> Processing backup: $($backup.Name)" -ForegroundColor Yellow
            
            try {
                if ($backup.Name -match '^\{[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}$') {
                    $backupId = $backup.Name -replace '[{}]', ''
                    
                    Write-Host "  -> Reading GPO information..." -ForegroundColor Yellow
                    $reportPath = Join-Path $backup.FullName "gpreport.xml"
                    
                    if (-not (Test-Path $reportPath)) {
                        Write-Error "  [X] GPO report file not found: $reportPath"
                        continue
                    }
                    
                    [xml]$report = Get-Content $reportPath
                    $gpoName = $report.GPO.Name
                    
                    # Check if this GPO should be imported
                    if ($gpoName -notin $gposToImport) {
                        Write-Host "  [!] Skipping GPO: $gpoName (not in list for current functional level)" -ForegroundColor Gray
                        continue
                    }
                    
                    Write-Host "  -> Importing GPO: $gpoName" -ForegroundColor Yellow
                    Write-Host "  -> Backup ID: $backupId" -ForegroundColor Gray
                    Write-Host "  -> Full path: $($backup.FullName)" -ForegroundColor Gray
                    
                    try {
                        # Use the absolute path for the backup
                        Import-GPO -BackupId $backupId -TargetName $gpoName -Path $absoluteBackupPath -Domain $TargetDomain -CreateIfNeeded -ErrorAction Stop
                        Write-Host "  [OK] GPO imported successfully" -ForegroundColor Green
                    }
                    catch {
                        Write-Error "  [X] Failed to import GPO: $_"
                        Write-Error "  [X] Please verify the following:"
                        Write-Error "     1. The GPO backup files are complete and not corrupted"
                        Write-Error "     2. You have sufficient permissions to import GPOs"
                        Write-Error "     3. The target domain is accessible"
                        Write-Error "     4. The backup path is correct: $absoluteBackupPath"
                        continue
                    }
                } else {
                    Write-Warning "  [!] Invalid backup folder format: $($backup.Name)"
                    Write-Warning "  [!] Expected format: {GUID}"
                }
            }
            catch {
                Write-Error "  [X] Failed to process GPO from folder $($backup.Name): $_"
                continue
            }
        }
        
        Write-Host "`n[OK] GPO import process completed" -ForegroundColor Green
    }
    catch {
        Write-Error "[X] GPO import process failed: $_"
        Write-Error "[X] Please verify the following:"
        Write-Error "    1. The backup path exists and is accessible"
        Write-Error "    2. You have sufficient permissions to read the backup files"
        Write-Error "    3. The target domain is accessible"
        Write-Error "    4. The backup path is correct: $absoluteBackupPath"
        throw
    }
}


function Set-GPOsToTiers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$TargetDomain,
        
        [Parameter(Mandatory=$true)]
        [string]$RootDN,
        
        [Parameter(Mandatory=$true)]
        [string[]]$TierNames,
        
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$gpoConfigPath
    )
    
    try {
        Write-Host "`n=== Applying GPOs to Tier Model ===" -ForegroundColor Cyan
        Write-Host "Target Domain: $TargetDomain" -ForegroundColor Yellow
        Write-Host "Root DN: $RootDN" -ForegroundColor Yellow
        
        # Load GPO configuration
        Write-Host "-> Loading GPO configuration from: $gpoConfigPath" -ForegroundColor Yellow
        $gpoConfig = Get-Content -Path $gpoConfigPath -Raw | ConvertFrom-Json
        
        if (-not $gpoConfig.TierMappings) {
            Write-Error "[X] TierMappings section not found in GPO configuration"
            return
        }
        
        foreach ($TierName in $TierNames) {
            Write-Host "`n-> Processing $TierName..." -ForegroundColor Yellow
            
            # Get the OU for this tier
            $TierOU = "OU=_$TierName,$RootDN"
            
            # Check if the OU exists
            try {
                Get-ADOrganizationalUnit -Identity $TierOU -ErrorAction Stop | Out-Null
                Write-Host "  -> Found OU: $TierOU" -ForegroundColor Green
            }
            catch {
                Write-Warning "  [!] OU not found: $TierOU"
                Write-Warning "  [!] Skipping GPO application for $TierName"
                continue
            }
            
            # Get GPOs for this tier from configuration
            $tierMapping = $gpoConfig.TierMappings.$TierName
            if (-not $tierMapping) {
                Write-Warning "  [!] No GPO mapping defined for $TierName in configuration"
                continue
            }
            
            $tierGPOs = $tierMapping.gpos
            Write-Host "  -> Description: $($tierMapping.description)" -ForegroundColor Gray
            Write-Host "  -> Applying $($tierGPOs.Count) GPOs to $TierName..." -ForegroundColor Yellow
            
            foreach ($gpoName in $tierGPOs) {
                try {
                    # Check if GPO exists
                    $gpo = Get-GPO -Name $gpoName -Domain $TargetDomain -ErrorAction SilentlyContinue
                    if (-not $gpo) {
                        Write-Warning "    [!] GPO not found: $gpoName"
                        continue
                    }
                    
                    # Link GPO to the tier OU
                    New-GPLink -Name $gpoName -Target $TierOU -Domain $TargetDomain -ErrorAction Stop
                    Write-Host "    [OK] Linked $gpoName to $TierOU" -ForegroundColor Green
                }
                catch {
                    Write-Error "    [X] Failed to link $gpoName to $TierOU"
                }
            }
        }
        
        Write-Host "`n[OK] GPO application to tier model completed" -ForegroundColor Green
    }
    catch {
        Write-Error "[X] Failed to apply GPOs to tier model: $_"
        throw
    }
}

# Export function
Export-ModuleMember -Function Import-SecurityHardeningGPOs, Set-GPOsToTiers 