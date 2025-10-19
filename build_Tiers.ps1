# Import required PowerShell modules
function Import-CoreModules {
    $modulesToImport = @("ActiveDirectory", "GroupPolicy", "LAPS")
    Write-Host "`n=== Loading Core PowerShell Modules ===" -ForegroundColor Cyan
    foreach ($module in $modulesToImport) {
        Write-Host "-> Loading $module module..." -ForegroundColor Yellow
        try { Import-Module $module -ErrorAction Stop } catch { Write-Error "[X] Failed to load $module module"; exit 1 }
    }
}

function Import-CustomModules {
    param([string]$scriptPath, [array]$customModules)
    Write-Host "`n=== Loading Custom Modules ===" -ForegroundColor Cyan
    Write-Host "Module source path: $scriptPath" -ForegroundColor Yellow
    foreach ($module in $customModules) {
        $moduleName = [System.IO.Path]::GetFileNameWithoutExtension($module)
        $modulePath = Join-Path $scriptPath "Modules\$module"
        if (-not (Test-Path $modulePath)) { Write-Error "[X] Module not found: $modulePath"; exit 1 }
        if (Get-Module -Name $moduleName) { Remove-Module -Name $moduleName -Force }
        try { Import-Module $modulePath -Force -DisableNameChecking } catch {
            Write-Error "[X] Failed to load $moduleName"
            exit 1
        }
        Write-Host "  [OK] Loaded $moduleName" -ForegroundColor Green
    }
}

function Test-ModuleImports {
    param([array]$customModules)
    Write-Host "`n=== Verifying Module Imports ===" -ForegroundColor Cyan
    foreach ($module in $customModules) {
        $moduleName = [System.IO.Path]::GetFileNameWithoutExtension($module)
        if (-not (Get-Module -Name $moduleName)) {
            Write-Error "[X] Module $moduleName not loaded properly"; exit 1
        }
    }
}

function Test-RequiredFunctions {
    param([array]$requiredFunctions)
    Write-Host "`n=== Verifying Required Functions ===" -ForegroundColor Cyan
    foreach ($function in $requiredFunctions) {
        if (-not (Get-Command -Name $function -ErrorAction SilentlyContinue)) {
            Write-Error "[X] Required function not found: $function"; exit 1
        }
    }
}

function Import-Configuration {
    param([string]$configPath)
    if (-not (Test-Path $configPath)) { Write-Error "[X] Config file missing: $configPath"; exit 1 }
    $script:Config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
    if (-not $script:Config.RootDN) { Write-Error "[X] Missing RootDN in config"; exit 1 }
    Write-Host "[OK] Configuration loaded. RootDN: $($script:Config.RootDN)" -ForegroundColor Green
}

function Invoke-Functions {
    param([System.Collections.Specialized.OrderedDictionary]$functionMappings)
    Write-Host "`n=== Main Execution ===" -ForegroundColor Cyan
    
    # Check if InitializeADStructure is enabled
    $initializeADStructure = $script:Config.Functions.InitializeADStructure
    
    foreach ($key in $functionMappings.Keys) {
        if ($script:Config.Functions.$key) {
            Write-Host "-> Executing $key..." -ForegroundColor Yellow
            
            # Special logic for GPO functions based on InitializeADStructure
            if ($key -eq "ApplyGPOsToTiers" -and -not $initializeADStructure) {
                Write-Host "[!] Skipping $key (InitializeADStructure is disabled)" -ForegroundColor Yellow
                continue
            }
            
            try { $functionMappings[$key].Invoke() } catch {
                Write-Error ("[X] Execution failed for " + $key + ": " + $_.Exception.Message)
                exit 1
            }
        } else {
            Write-Host "[!] Skipping $key (disabled in config)" -ForegroundColor Yellow
        }
    }
}

function Test-FunctionalLevel {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$TargetDomain
    )
    
    try {
        Write-Host "`n=== Checking Forest and Domain Functional Levels ===" -ForegroundColor Cyan
        $forest = Get-ADForest -Identity $TargetDomain
        $domain = Get-ADDomain -Identity $TargetDomain
        Write-Host "Forest Functional Level: $($forest.ForestMode)" -ForegroundColor Yellow
        Write-Host "Domain Functional Level: $($domain.DomainMode)" -ForegroundColor Yellow
        $forestLevel = switch -regex ($forest.ForestMode) {
            '(\d+)Forest' { [int]$matches[1] }
            default { throw "Unsupported forest functional level format: $_" }
        }
        $domainLevel = switch -regex ($domain.DomainMode) {
            '(\d+)Domain' { [int]$matches[1] }
            default { throw "Unsupported domain functional level format: $_" }
        }
        return @{
            ForestLevel = $forestLevel
            DomainLevel = $domainLevel
        }
    }
    catch {
        Write-Error "[X] Failed to check functional levels: $_"
        throw
    }
}

# Main Execution
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$customModules = @("Common.psm1", "GPO.psm1", "ADSecurity.psm1", "ADStructure.psm1")
$requiredFunctions = @("Initialize-ADStructure", "New-OU", "New-Group", "Import-SecurityHardeningGPOs", "Set-GPOsToTiers", "Set-ADSIUnauthenticatedBind", "Set-msDSMachineAccountQuota", "Set-KrbtgtEncryption", "Enable-RecycleBin", "Enable-LAPS", "Enable-Bitlocker")
$configPath = Join-Path $scriptPath "Config\Global_config.json"
$gpoConfigPath = Join-Path $scriptPath "Config\GPO_config.json"


$functionMappings = [ordered]@{
    "InitializeADStructure" = { Initialize-ADStructure -RootDN $script:Config.RootDN -AdmName $script:Config.AdmName -TierNames $script:Config.TierNames -SubOUs $script:Config.SubOUs -Tier0and1SubOUs $script:Config.Tier0and1SubOUs -DisabledOU $script:Config.DisabledOU }
    "ImportSecurityHardeningGPOs" = { Import-SecurityHardeningGPOs -BackupPath $script:Config.GPOBackupPath -TargetDomain $script:Config.TargetDomain -FunctionalLevels $functionalLevels -gpoConfigPath $gpoConfigPath }
    "ApplyGPOsToTiers" = { Set-GPOsToTiers -TargetDomain $script:Config.TargetDomain -RootDN $script:Config.RootDN -TierNames $script:Config.TierNames -gpoConfigPath $gpoConfigPath }
    "SetADSIUnauthenticatedBind" = { Set-ADSIUnauthenticatedBind -TargetDomain $script:Config.TargetDomain }
    "SetmsDSMachineAccountQuota" = { Set-msDSMachineAccountQuota -TargetDomain $script:Config.TargetDomain }
    "SetmsDSSupportedEncryptionTypes-krbtgt" = { Set-KrbtgtEncryption }
    "EnableRecycleBin" = { Enable-RecycleBin -TargetDomain $script:Config.TargetDomain -FunctionalLevels $functionalLevels }
    "EnableLAPS" = { Enable-LAPS -TargetDomain $script:Config.TargetDomain }
    "EnableBitlocker" = { Enable-BitLocker }
}

Import-CoreModules
Import-CustomModules -scriptPath $scriptPath -customModules $customModules
Test-ModuleImports -customModules $customModules
Test-RequiredFunctions -requiredFunctions $requiredFunctions
Import-Configuration -configPath $configPath
$functionalLevels = Test-FunctionalLevel -TargetDomain $script:Config.TargetDomain
Invoke-Functions -functionMappings $functionMappings
