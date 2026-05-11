<#
.SYNOPSIS
    Deploy a tiered Active Directory administration model with hardening GPOs.

.DESCRIPTION
    Orchestrates the Sec_AD project:
      1. Loads core and custom PowerShell modules
      2. Initializes file logging
      3. Runs preflight checks (modules, privileges, connectivity, config)
      4. Captures an AD state baseline for rollback
      5. Executes enabled functions from the configuration

.PARAMETER ConfigPath
    Path to Global_config.json. Default: .\Config\Global_config.json

.PARAMETER GpoConfigPath
    Path to GPO_config.json. Default: .\Config\GPO_config.json

.PARAMETER LogLevel
    Minimum log level written to file and console (DEBUG/INFO/WARN/ERROR). Default: INFO.

.PARAMETER DryRun
    Show what would be done without applying any change. Implies preflight + state backup,
    but skips the actual function execution. Use this on the first run.

.PARAMETER SkipPreflight
    Skip preflight checks. NOT RECOMMENDED. For automation scenarios where checks are external.

.PARAMETER SkipBackup
    Skip the AD state baseline capture. NOT RECOMMENDED for production runs.

.EXAMPLE
    .\sec_ad.ps1 -DryRun
    Validate environment and show planned changes without modifying AD.

.EXAMPLE
    .\sec_ad.ps1 -LogLevel DEBUG
    Run with verbose logging.

.EXAMPLE
    .\sec_ad.ps1 -WhatIf
    Standard PowerShell WhatIf semantics for cmdlets that support it.

.NOTES
    Run as Domain Administrator. Always test in a lab before production.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()] [string]$ConfigPath,
    [Parameter()] [string]$GpoConfigPath,

    [Parameter()]
    [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')]
    [string]$LogLevel = 'INFO',

    [Parameter()] [switch]$DryRun,
    [Parameter()] [switch]$SkipPreflight,
    [Parameter()] [switch]$SkipBackup
)


$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ConfigPath)    { $ConfigPath    = Join-Path $scriptPath 'Config\Global_config.json' }
if (-not $GpoConfigPath) { $GpoConfigPath = Join-Path $scriptPath 'Config\GPO_config.json' }
$logDir    = Join-Path $scriptPath 'logs'
$backupDir = Join-Path $scriptPath 'backups'


function Import-CoreModules {
    # Temporarily disable WhatIf for module loading (Import-Module does not support -WhatIf)
    $savedWhatIf = $WhatIfPreference
    $WhatIfPreference = $false
    try {
        $modulesToImport = @('ActiveDirectory', 'GroupPolicy', 'LAPS')
        foreach ($module in $modulesToImport) {
            try {
                Import-Module $module -ErrorAction Stop
            } catch {
                # LAPS is optional; warn but don't abort
                if ($module -eq 'LAPS') {
                    Write-Warning "LAPS module not available (optional): $($_.Exception.Message)"
                } else {
                    Write-Error "Failed to load $module module: $($_.Exception.Message)"
                    exit 1
                }
            }
        }
    } finally {
        $WhatIfPreference = $savedWhatIf
    }
}

function Import-CustomModules {
    param([string]$ScriptPath, [array]$CustomModules)
    # Same: Import-Module / Remove-Module don't both support -WhatIf consistently
    $savedWhatIf = $WhatIfPreference
    $WhatIfPreference = $false
    try {
        foreach ($module in $CustomModules) {
            $moduleName = [System.IO.Path]::GetFileNameWithoutExtension($module)
            $modulePath = Join-Path $ScriptPath "Modules\$module"
            if (-not (Test-Path $modulePath)) {
                Write-Error "Module not found: $modulePath"
                exit 1
            }
            if (Get-Module -Name $moduleName) {
                Remove-Module -Name $moduleName -Force
            }
            try {
                Import-Module $modulePath -Force -DisableNameChecking -ErrorAction Stop
            } catch {
                Write-Error "Failed to load ${moduleName}: $($_.Exception.Message)"
                exit 1
            }
        }
    } finally {
        $WhatIfPreference = $savedWhatIf
    }
}


function Test-FunctionalLevel {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$TargetDomain)
    try {
        Write-Log "`n=== Checking Forest and Domain Functional Levels ===" -Level INFO -Color Cyan
        $forest = Get-ADForest -Identity $TargetDomain
        $domain = Get-ADDomain -Identity $TargetDomain
        Write-Log "Forest Functional Level: $($forest.ForestMode)" -Level INFO
        Write-Log "Domain Functional Level: $($domain.DomainMode)" -Level INFO
        $forestLevel = switch -regex ($forest.ForestMode) {
            '(\d+)Forest' { [int]$matches[1] }
            default       { throw "Unsupported forest functional level format: $_" }
        }
        $domainLevel = switch -regex ($domain.DomainMode) {
            '(\d+)Domain' { [int]$matches[1] }
            default       { throw "Unsupported domain functional level format: $_" }
        }
        return @{ ForestLevel = $forestLevel; DomainLevel = $domainLevel }
    } catch {
        Write-Log "Failed to check functional levels: $_" -Level ERROR
        throw
    }
}


function Invoke-Functions {
    param(
        [System.Collections.Specialized.OrderedDictionary]$FunctionMappings,
        [switch]$DryRun
    )
    Write-Log "`n=== Main Execution ===" -Level INFO -Color Cyan

    $initializeADStructure = $script:Config.Functions.InitializeADStructure

    foreach ($key in $FunctionMappings.Keys) {
        if (-not $script:Config.Functions.$key) {
            Write-Log "[!] Skipping $key (disabled in config)" -Level WARN
            continue
        }

        if ($key -eq 'ApplyGPOsToTiers' -and -not $initializeADStructure) {
            Write-Log "[!] Skipping $key (InitializeADStructure is disabled)" -Level WARN
            continue
        }

        if ($DryRun) {
            Write-Log "[DRY-RUN] Would execute: $key" -Level INFO -Color Magenta
            continue
        }

        Write-Log "-> Executing $key..." -Level INFO -Color Yellow
        try {
            $FunctionMappings[$key].Invoke()
            Write-Log "[OK] $key completed" -Level SUCCESS
        } catch {
            Write-Log "Execution failed for ${key}: $($_.Exception.Message)" -Level ERROR
            throw
        }
    }
}


# 1. Import modules
$customModules = @(
    'Logging.psm1',
    'Validation.psm1',
    'StateManagement.psm1',
    'GPO.psm1',
    'ADStructure.psm1',
    'ADHardening.psm1'
)

Write-Host "`n=== Loading Modules ===" -ForegroundColor Cyan
Import-CoreModules
Import-CustomModules -ScriptPath $scriptPath -CustomModules $customModules

# 2. Init logging
Initialize-Logging -LogDirectory $logDir -Level $LogLevel | Out-Null
Write-Log "Sec_AD started" -Level INFO -Color Cyan
if ($DryRun) { Write-Log "Mode: DRY-RUN (no changes will be applied)" -Level WARN }

# 3. Load configuration
if (-not (Test-Path $ConfigPath)) {
    Write-Log "Config file missing: $ConfigPath" -Level ERROR
    exit 1
}
$script:Config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
if (-not $script:Config.RootDN) {
    Write-Log "Missing RootDN in config" -Level ERROR
    exit 1
}
Write-Log "[OK] Configuration loaded. RootDN: $($script:Config.RootDN)" -Level SUCCESS

# 3b. Resolve relative paths from the configuration to absolute paths.
#     The script can be invoked from any working directory; all paths in the
#     config are interpreted relative to the script's own directory.
if ([System.IO.Path]::IsPathRooted($script:Config.GPOBackupPath)) {
    $gpoBackupPath = $script:Config.GPOBackupPath
} else {
    $gpoBackupPath = Join-Path $scriptPath $script:Config.GPOBackupPath
}
Write-Log "GPO backup path resolved to: $gpoBackupPath" -Level DEBUG

# 4. Preflight
if (-not $SkipPreflight) {
    $preflightOk = Invoke-PreflightChecks `
        -TargetDomain $script:Config.TargetDomain `
        -ConfigPath $ConfigPath `
        -GpoConfigPath $GpoConfigPath `
        -GPOBackupPath $gpoBackupPath
    if (-not $preflightOk) {
        Write-Log "Aborting due to preflight failures." -Level ERROR
        exit 1
    }
} else {
    Write-Log "[!] Preflight checks skipped" -Level WARN
}

# 5. Functional level (needed by some functions)
$functionalLevels = Test-FunctionalLevel -TargetDomain $script:Config.TargetDomain

# 6. State backup
if (-not $SkipBackup) {
    New-StateBackup `
        -BackupDirectory $backupDir `
        -RootDN $script:Config.RootDN `
        -TargetDomain $script:Config.TargetDomain `
        -TierNames $script:Config.TierNames `
        -AdmName $script:Config.AdmName | Out-Null
} else {
    Write-Log "[!] State backup skipped" -Level WARN
}

# 7. Function mappings
$functionMappings = [ordered]@{
    'InitializeADStructure'                 = { Initialize-ADStructure -RootDN $script:Config.RootDN -AdmName $script:Config.AdmName -TierNames $script:Config.TierNames -SubOUs $script:Config.SubOUs -Tier0and1SubOUs $script:Config.Tier0and1SubOUs -DisabledOU $script:Config.DisabledOU }
    'ImportSecurityHardeningGPOs'           = { Import-SecurityHardeningGPOs -BackupPath $gpoBackupPath -TargetDomain $script:Config.TargetDomain -FunctionalLevels $functionalLevels -gpoConfigPath $GpoConfigPath }
    'ApplyGPOsToTiers'                      = { Set-GPOsToTiers -TargetDomain $script:Config.TargetDomain -RootDN $script:Config.RootDN -TierNames $script:Config.TierNames -gpoConfigPath $GpoConfigPath }
    'SetADSIUnauthenticatedBind'            = { Set-ADSIUnauthenticatedBind -TargetDomain $script:Config.TargetDomain }
    'SetmsDSMachineAccountQuota'            = { Set-msDSMachineAccountQuota -TargetDomain $script:Config.TargetDomain }
    'SetmsDSSupportedEncryptionTypes-krbtgt'= { Set-KerberosEncryptionTypes }
    'EnableRecycleBin'                      = { Enable-RecycleBin -TargetDomain $script:Config.TargetDomain -FunctionalLevels $functionalLevels }
    'EnableLAPS'                            = { Enable-LAPS -TargetDomain $script:Config.TargetDomain }
    'EnableBitlocker'                       = { Enable-BitLocker }
    'SetTierOUDelegation'                   = {
        $aclBackupDir = Join-Path $backupDir 'acl'
        $tierAdminMap = @{
            'Tier0'        = 'Tier0_Admins'
            'Tier1'        = 'Tier1_Admins'
            'Tier2'        = 'Tier2_Admins'
            'Tier1_Legacy' = 'Tier1_Legacy_Admins'
        }
        foreach ($tier in $script:Config.TierNames) {
            if (-not $tierAdminMap.ContainsKey($tier)) { continue }
            $self     = $tierAdminMap[$tier]
            $others   = $script:Config.TierNames |
                        Where-Object { $_ -ne $tier -and $tierAdminMap.ContainsKey($_) } |
                        ForEach-Object { $tierAdminMap[$_] }
            Set-TierOUDelegation `
                -TierName $tier `
                -RootDN $script:Config.RootDN `
                -AdminGroupName $self `
                -OtherTierAdminGroups $others `
                -BackupDirectory $aclBackupDir
        }
    }
    'NewTier0AuthenticationPolicySilo'      = {
        $siloConfigPath = Join-Path $scriptPath 'Config\Silo_config.json'
        New-Tier0AuthenticationPolicySilo `
            -FunctionalLevels $functionalLevels `
            -SiloConfigPath $siloConfigPath
    }
    'LockPreWindows2000Group'               = { Lock-PreWindows2000Group -BackupDirectory $backupDir }
    'GetPrivilegedGroupAudit'               = {
        $reportFile = Join-Path $logDir "privileged_audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        Get-PrivilegedGroupAudit -ReportPath $reportFile | Out-Null
    }
    'SetTier0AccountSensitive'              = { Set-Tier0AccountSensitive -RootDN $script:Config.RootDN }
    'CompareStateBackup'                    = {
        $latest = Get-LatestStateBackup -BackupDirectory $backupDir
        if (-not $latest) { Write-Log "No state backup found in: $backupDir" -Level WARN; return }
        $diff = Compare-StateBackup -BackupFile $latest.FullName
        Write-Log "Backup : $($diff.Timestamp)  ($($latest.Name))" -Level INFO
        Write-Log "Domain attributes to restore : $($diff.DomainAttrs.Count)" -Level INFO
        Write-Log "OUs to delete                : $($diff.OUsToDelete.Count)" -Level INFO
        Write-Log "Groups to delete             : $($diff.GroupsToDelete.Count)" -Level INFO
        Write-Log "GPO links to remove          : $($diff.LinksToRemove.Count)" -Level INFO
        Write-Log "GPO links to re-add          : $($diff.LinksToReadd.Count)" -Level INFO
        foreach ($n in $diff.Notes) { Write-Log "Note: $n" -Level WARN }
    }
    'RestoreStateBackup'                    = {
        $latest = Get-LatestStateBackup -BackupDirectory $backupDir
        if (-not $latest) { throw "No state backup found in: $backupDir. Run a deployment first." }
        Write-Log "[!] Restoring AD state from: $($latest.Name)" -Level WARN
        Restore-StateBackup -BackupFile $latest.FullName -All -Confirm:$false
    }
}

# 8. Execute
Invoke-Functions -FunctionMappings $functionMappings -DryRun:$DryRun

Write-Log "`n=== Sec_AD execution finished ===" -Level SUCCESS -Color Cyan
Write-Log "Log file: $(Get-LogFilePath)" -Level INFO
