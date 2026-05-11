<#
.SYNOPSIS
    GPO import and tier-linking functions for Sec_AD.

.DESCRIPTION
    Handles two phases of GPO deployment:
      1. Import  : reads GPO backup folders ({GUID} format) and imports them into the domain
                   via Import-GPO; functional-level filters control which GPOs are included.
      2. Linking : links each imported GPO to the appropriate tier OU (or sub-OU) based on
                   the TierMappings section of GPO_config.json. Operations are idempotent.

    Functions exported:
      - Import-SecurityHardeningGPOs : import GPO backups from a local directory into the domain
      - Set-GPOsToTiers              : link GPOs to tier OUs as configured in GPO_config.json
      - Resolve-TierSubOUMapping     : (internal) resolve tier config to a list of {OU, GPOs} pairs
#>

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
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({
            if (Test-Path -Path $_ -PathType Container) { return $true }
            throw "BackupPath does not exist or is not a directory: '$_'. " +
                  "If this is a relative path, it is resolved from: '$PWD'. " +
                  "Pass an absolute path or run the script from the repo root."
        })]
        [string]$BackupPath,

        [Parameter(Mandatory=$true)] [string]$TargetDomain,
        [Parameter(Mandatory=$true)] [hashtable]$FunctionalLevels,

        [Parameter(Mandatory=$true)]
        [ValidateScript({
            if (Test-Path -Path $_ -PathType Leaf) { return $true }
            throw "gpoConfigPath does not point to an existing file: '$_'"
        })]
        [string]$gpoConfigPath
    )

    try {
        Write-Log "`n=== Importing Security Hardening GPOs ===" -Level INFO -Color Cyan
        $script:gpoConfig = Get-Content -Path $gpoConfigPath -Raw | ConvertFrom-Json
        $gposToImport = Get-GPOsToImport -FunctionalLevels $FunctionalLevels -GPOConfig $script:gpoConfig
        $absoluteBackupPath = (Resolve-Path $BackupPath).Path
        Write-Log "Source path: $absoluteBackupPath" -Level INFO

        Write-Log "`n-> Scanning for GPO backups..." -Level INFO
        $gpoBackups = Get-ChildItem -Path $absoluteBackupPath -Directory
        Write-Log "  Found $($gpoBackups.Count) backup folders" -Level DEBUG
        Write-Log "  Total GPOs to import: $($gposToImport.Count)" -Level DEBUG

        if ($gpoBackups.Count -eq 0) {
            Write-Error "[X] No GPO backup folders found in: $absoluteBackupPath"
            Write-Error "[X] Please ensure the GPO backup files are present in the specified directory"
            return
        }

        foreach ($backup in $gpoBackups) {
            Write-Log "`n-> Processing backup: $($backup.Name)" -Level INFO

            try {
                if ($backup.Name -match '^\{[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}$') {
                    $backupId  = $backup.Name -replace '[{}]', ''
                    $reportPath = Join-Path $backup.FullName "gpreport.xml"

                    if (-not (Test-Path $reportPath)) {
                        Write-Error "  [X] GPO report file not found: $reportPath"
                        continue
                    }

                    [xml]$report = Get-Content $reportPath
                    $gpoName = $report.GPO.Name

                    if ($gpoName -notin $gposToImport) {
                        Write-Log "  [!] Skipping GPO: $gpoName (not in list for current functional level)" -Level DEBUG
                        continue
                    }

                    Write-Log "  -> Importing GPO: $gpoName" -Level INFO
                    Write-Log "  -> Backup ID: $backupId  Path: $($backup.FullName)" -Level DEBUG

                    try {
                        if ($PSCmdlet.ShouldProcess($gpoName, "Import GPO from $($backup.FullName)")) {
                            Import-GPO -BackupId $backupId -TargetName $gpoName -Path $absoluteBackupPath -Domain $TargetDomain -CreateIfNeeded -ErrorAction Stop
                            Write-Log "  [OK] GPO imported successfully" -Level SUCCESS
                        }
                    } catch {
                        Write-Error "  [X] Failed to import GPO: $_"
                        Write-Error "  [X] Verify: backup complete, sufficient permissions, domain accessible, path correct: $absoluteBackupPath"
                        continue
                    }
                } else {
                    Write-Warning "  [!] Invalid backup folder format (expected {GUID}): $($backup.Name)"
                }
            } catch {
                Write-Error "  [X] Failed to process GPO from folder $($backup.Name): $_"
                continue
            }
        }

        Write-Log "`n[OK] GPO import process completed" -Level SUCCESS
    } catch {
        Write-Error "[X] GPO import process failed: $_"
        Write-Error "[X] Verify: backup path exists, sufficient permissions, domain accessible, path: $absoluteBackupPath"
        throw
    }
}

function Resolve-TierSubOUMapping {
    <#
    .SYNOPSIS
        Returns an ordered list of @{ OU = <DN>; GPOs = @(...) } pairs from a tier mapping.
    .DESCRIPTION
        Supports two configuration formats:
          - New (granular): tier mapping has a "subOUs" object whose keys are sub-OU names
            (or "_root" for the tier OU itself). Each value has a "gpos" array.
          - Legacy (flat):  tier mapping has a top-level "gpos" array, applied to the tier root.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $TierMapping,
        [Parameter(Mandatory)] [string]$TierName,
        [Parameter(Mandatory)] [string]$RootDN
    )

    $result   = [System.Collections.Generic.List[object]]::new()
    $tierRoot = "OU=_$TierName,$RootDN"

    if ($TierMapping.PSObject.Properties.Name -contains 'subOUs' -and $TierMapping.subOUs) {
        foreach ($prop in $TierMapping.subOUs.PSObject.Properties) {
            $ouName = $prop.Name
            $entry  = $prop.Value
            if (-not $entry.gpos -or $entry.gpos.Count -eq 0) { continue }
            $targetOU = if ($ouName -eq '_root') { $tierRoot } else { "OU=$ouName,$tierRoot" }
            $result.Add([PSCustomObject]@{
                OU       = $targetOU
                GPOs     = @($entry.gpos)
                IsRoot   = ($ouName -eq '_root')
                SubOUKey = $ouName
            })
        }
    } elseif ($TierMapping.gpos) {
        $result.Add([PSCustomObject]@{
            OU       = $tierRoot
            GPOs     = @($TierMapping.gpos)
            IsRoot   = $true
            SubOUKey = '_root'
        })
    }

    return $result
}

function Set-GPOsToTiers {
    <#
    .SYNOPSIS Link GPOs to tier OUs and sub-OUs based on configuration.
    .DESCRIPTION
        Reads TierMappings from the GPO config and links each GPO to the configured OU.
        Supports both granular (subOUs) and legacy (flat gpos) formats.
        Operations are idempotent: existing links are detected and skipped.
        Link order is preserved as configured (first GPO listed = highest precedence within the OU).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory=$true)] [string]$TargetDomain,
        [Parameter(Mandatory=$true)] [string]$RootDN,
        [Parameter(Mandatory=$true)] [string[]]$TierNames,

        [Parameter(Mandatory=$true)]
        [ValidateScript({
            if (Test-Path -Path $_ -PathType Leaf) { return $true }
            throw "gpoConfigPath does not point to an existing file: '$_'"
        })]
        [string]$gpoConfigPath
    )

    try {
        Write-Log "`n=== Applying GPOs to Tier Model ===" -Level INFO -Color Cyan
        Write-Log "Target Domain: $TargetDomain" -Level INFO
        Write-Log "Root DN      : $RootDN"       -Level INFO

        Write-Log "-> Loading GPO configuration from: $gpoConfigPath" -Level INFO
        $gpoConfig = Get-Content -Path $gpoConfigPath -Raw | ConvertFrom-Json

        if (-not $gpoConfig.TierMappings) {
            Write-Error "[X] TierMappings section not found in GPO configuration"
            return
        }

        $summary = [PSCustomObject]@{
            Linked        = 0
            AlreadyLinked = 0
            Skipped_NoGPO = 0
            Skipped_NoOU  = 0
            Failed        = 0
        }

        foreach ($TierName in $TierNames) {
            Write-Log "`n-> Processing tier: $TierName" -Level INFO

            $tierMapping = $gpoConfig.TierMappings.$TierName
            if (-not $tierMapping) {
                Write-Warning "  [!] No mapping for $TierName in configuration"
                continue
            }
            if ($tierMapping.description) {
                Write-Log "  Description: $($tierMapping.description)" -Level DEBUG
            }

            $targets = Resolve-TierSubOUMapping -TierMapping $tierMapping -TierName $TierName -RootDN $RootDN
            if ($targets.Count -eq 0) {
                Write-Warning "  [!] No OUs / GPOs configured for $TierName"
                continue
            }

            foreach ($target in $targets) {
                $TargetOU = $target.OU
                $tierGPOs = $target.GPOs
                Write-Log "`n  -> OU: $TargetOU" -Level INFO -Color Cyan
                Write-Log "     GPOs configured: $($tierGPOs.Count)" -Level DEBUG

                try {
                    Get-ADOrganizationalUnit -Identity $TargetOU -ErrorAction Stop | Out-Null
                } catch {
                    Write-Warning "     [!] OU not found, skipping: $TargetOU"
                    $summary.Skipped_NoOU += $tierGPOs.Count
                    continue
                }

                $existingLinks = @()
                try {
                    $existingLinks = (Get-GPInheritance -Target $TargetOU -Domain $TargetDomain -ErrorAction Stop).GpoLinks
                } catch {
                    Write-Warning "     [!] Could not enumerate existing links: $($_.Exception.Message)"
                }
                $existingNames = @($existingLinks | ForEach-Object { $_.DisplayName })

                foreach ($gpoName in $tierGPOs) {
                    try {
                        $gpo = Get-GPO -Name $gpoName -Domain $TargetDomain -ErrorAction SilentlyContinue
                        if (-not $gpo) {
                            Write-Warning "     [!] GPO not found in domain: $gpoName"
                            $summary.Skipped_NoGPO++
                            continue
                        }

                        if ($existingNames -contains $gpoName) {
                            Write-Log "     [=] Already linked: $gpoName" -Level DEBUG
                            $summary.AlreadyLinked++
                            continue
                        }

                        if ($PSCmdlet.ShouldProcess($TargetOU, "Link GPO '$gpoName'")) {
                            New-GPLink -Name $gpoName -Target $TargetOU -Domain $TargetDomain -LinkEnabled Yes -ErrorAction Stop | Out-Null
                            Write-Log "     [OK] Linked: $gpoName" -Level SUCCESS
                            $summary.Linked++
                        }
                    } catch {
                        Write-Error "     [X] Failed to link '$gpoName' to ${TargetOU}: $($_.Exception.Message)"
                        $summary.Failed++
                    }
                }
            }
        }

        Write-Log "`n=== GPO Linking Summary ===" -Level INFO -Color Cyan
        Write-Log ("  Newly linked             : {0}" -f $summary.Linked)          -Level SUCCESS
        Write-Log ("  Already linked           : {0}" -f $summary.AlreadyLinked)   -Level DEBUG
        Write-Log ("  Skipped (no GPO in domain): {0}" -f $summary.Skipped_NoGPO) -Level WARN
        Write-Log ("  Skipped (OU missing)      : {0}" -f $summary.Skipped_NoOU)  -Level WARN
        $failedLevel = if ($summary.Failed -gt 0) { 'ERROR' } else { 'DEBUG' }
        Write-Log ("  Failed                   : {0}" -f $summary.Failed)          -Level $failedLevel
    } catch {
        Write-Error "[X] Failed to apply GPOs to tier model: $_"
        throw
    }
}

Export-ModuleMember -Function Import-SecurityHardeningGPOs, Set-GPOsToTiers, Resolve-TierSubOUMapping
