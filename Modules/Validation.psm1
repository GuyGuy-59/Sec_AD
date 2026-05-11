<#
.SYNOPSIS
    Pre-execution validation checks for the Sec_AD project.

.DESCRIPTION
    Verifies that the runtime environment is suitable before any AD modification:
    - PowerShell version
    - Required modules with minimum versions
    - Domain Admin / Enterprise Admin privileges
    - Connectivity to target domain
    - Configuration file integrity
    - GPO backup folders presence and validity
#>

function Test-PSVersion {
    [CmdletBinding()]
    param(
        [Parameter()] [version]$MinVersion = '5.1'
    )
    $current = $PSVersionTable.PSVersion
    if ($current -lt $MinVersion) {
        Write-Log "PowerShell $MinVersion+ required. Current: $current" -Level ERROR
        return $false
    }
    Write-Log "  [OK] PowerShell version: $current" -Level SUCCESS
    return $true
}

function Test-RequiredModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter()] [version]$MinVersion
    )

    # Standard lookup
    $module = Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue |
              Sort-Object Version -Descending |
              Select-Object -First 1

    # PowerShell 7+ fallback: some RSAT modules (e.g. GroupPolicy) are Desktop-edition only and
    # load via the WindowsCompatibility session. Try -SkipEditionCheck and verify it can actually
    # be imported. If it imports, we accept it even if Get-Module -ListAvailable hides it.
    if (-not $module -and $PSVersionTable.PSVersion.Major -ge 7) {
        $module = Get-Module -ListAvailable -Name $Name -SkipEditionCheck -ErrorAction SilentlyContinue |
                  Sort-Object Version -Descending |
                  Select-Object -First 1
        if (-not $module) {
            # Import-Module does not support -WhatIf, so suppress preference locally
            $savedWhatIf = $WhatIfPreference
            $WhatIfPreference = $false
            try {
                Import-Module $Name -SkipEditionCheck -ErrorAction Stop -WarningAction SilentlyContinue
                $module = Get-Module -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
            } catch {
                # leave $module null
            } finally {
                $WhatIfPreference = $savedWhatIf
            }
        }
    }

    if (-not $module) {
        Write-Log "  [X] Module not installed: $Name" -Level ERROR
        return $false
    }
    if ($MinVersion -and $module.Version -lt $MinVersion) {
        Write-Log "  [X] $Name version $($module.Version) below required $MinVersion" -Level ERROR
        return $false
    }
    $edition = if ($module.CompatiblePSEditions) { " [$($module.CompatiblePSEditions -join ',')]" } else { '' }
    Write-Log "  [OK] $Name $($module.Version)$edition" -Level SUCCESS
    return $true
}

function Test-AdminPrivileges {
    [CmdletBinding()]
    param(
        [Parameter()] [string]$TargetDomain
    )
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Log "  [X] Script not running as local Administrator" -Level ERROR
            return $false
        }
        Write-Log "  [OK] Running as local Administrator" -Level SUCCESS

        if ($TargetDomain) {
            # Check Domain Admins membership (best-effort: warn if not in DA)
            $userName = $currentUser.Name.Split('\')[-1]
            try {
                $daGroup = Get-ADGroupMember -Identity 'Domain Admins' -Recursive -Server $TargetDomain -ErrorAction Stop |
                           Where-Object { $_.SamAccountName -eq $userName }
                if (-not $daGroup) {
                    Write-Log "  [!] Current user is not a member of Domain Admins (some operations may fail)" -Level WARN
                } else {
                    Write-Log "  [OK] Domain Admin membership confirmed" -Level SUCCESS
                }
            } catch {
                Write-Log "  [!] Could not verify Domain Admin membership: $($_.Exception.Message)" -Level WARN
            }
        }
        return $true
    } catch {
        Write-Log "  [X] Privilege check failed: $_" -Level ERROR
        return $false
    }
}

function Test-DomainConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$TargetDomain
    )
    try {
        $domain = Get-ADDomain -Identity $TargetDomain -ErrorAction Stop
        Write-Log "  [OK] Connected to domain $($domain.DNSRoot) (DC: $($domain.PDCEmulator))" -Level SUCCESS
        return $true
    } catch {
        Write-Log "  [X] Cannot reach domain ${TargetDomain}: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Test-Configuration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ConfigPath,
        [Parameter(Mandatory)] [string[]]$RequiredKeys
    )
    if (-not (Test-Path $ConfigPath)) {
        Write-Log "  [X] Config file not found: $ConfigPath" -Level ERROR
        return $false
    }
    try {
        $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    } catch {
        Write-Log "  [X] Config file is not valid JSON: $($_.Exception.Message)" -Level ERROR
        return $false
    }
    $missing = @()
    foreach ($key in $RequiredKeys) {
        if (-not $config.PSObject.Properties.Name.Contains($key) -or [string]::IsNullOrWhiteSpace($config.$key)) {
            $missing += $key
        }
    }
    if ($missing.Count -gt 0) {
        Write-Log "  [X] Missing required config keys: $($missing -join ', ')" -Level ERROR
        return $false
    }
    Write-Log "  [OK] Configuration $ConfigPath valid" -Level SUCCESS
    return $true
}

function Test-GPOBackups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$BackupPath,
        [Parameter()] [string[]]$ExpectedGPONames
    )
    if (-not (Test-Path $BackupPath)) {
        Write-Log "  [X] GPO backup path not found: $BackupPath" -Level ERROR
        return $false
    }
    $folders = Get-ChildItem -Path $BackupPath -Directory |
               Where-Object { $_.Name -match '^\{[0-9a-fA-F\-]{36}\}$' }
    if ($folders.Count -eq 0) {
        Write-Log "  [X] No valid GPO backup folders (expected {GUID} format) in $BackupPath" -Level ERROR
        return $false
    }
    Write-Log "  [OK] Found $($folders.Count) GPO backup folder(s)" -Level SUCCESS

    if ($ExpectedGPONames) {
        $foundNames = @()
        foreach ($folder in $folders) {
            $reportPath = Join-Path $folder.FullName 'gpreport.xml'
            if (Test-Path $reportPath) {
                try {
                    [xml]$xml = Get-Content $reportPath -ErrorAction Stop
                    $foundNames += $xml.GPO.Name
                } catch {
                    Write-Log "  [!] Could not parse $reportPath" -Level WARN
                }
            }
        }
        $missing = $ExpectedGPONames | Where-Object { $_ -notin $foundNames }
        if ($missing.Count -gt 0) {
            Write-Log "  [!] Configured GPOs not found in backups: $($missing -join ', ')" -Level WARN
        }
    }
    return $true
}

function Invoke-PreflightChecks {
    <#
    .SYNOPSIS Run all preflight checks. Returns $true if all pass.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$TargetDomain,
        [Parameter(Mandatory)] [string]$ConfigPath,
        [Parameter(Mandatory)] [string]$GpoConfigPath,
        [Parameter()] [string]$GPOBackupPath,
        [Parameter()] [switch]$SkipPrivilegeCheck
    )

    Write-Log "`n=== Preflight Checks ===" -Level INFO -Color Cyan
    $allOk = $true

    Write-Log "-> PowerShell version" -Level INFO -Color Yellow
    if (-not (Test-PSVersion -MinVersion '5.1')) { $allOk = $false }

    Write-Log "-> Required modules" -Level INFO -Color Yellow
    if (-not (Test-RequiredModule -Name 'ActiveDirectory')) { $allOk = $false }
    if (-not (Test-RequiredModule -Name 'GroupPolicy'))     { $allOk = $false }
    # LAPS module is optional (only on DCs that have it installed)
    Test-RequiredModule -Name 'LAPS' | Out-Null

    if (-not $SkipPrivilegeCheck) {
        Write-Log "-> Privileges" -Level INFO -Color Yellow
        if (-not (Test-AdminPrivileges -TargetDomain $TargetDomain)) { $allOk = $false }
    }

    Write-Log "-> Domain connectivity" -Level INFO -Color Yellow
    if (-not (Test-DomainConnectivity -TargetDomain $TargetDomain)) { $allOk = $false }

    Write-Log "-> Configuration files" -Level INFO -Color Yellow
    $globalKeys = @('RootDN', 'AdmName', 'TierNames', 'TargetDomain', 'GPOBackupPath')
    if (-not (Test-Configuration -ConfigPath $ConfigPath -RequiredKeys $globalKeys)) { $allOk = $false }
    if (-not (Test-Configuration -ConfigPath $GpoConfigPath -RequiredKeys @('GPOs'))) { $allOk = $false }

    if ($GPOBackupPath) {
        Write-Log "-> GPO backups" -Level INFO -Color Yellow
        if (-not (Test-Path $GPOBackupPath -PathType Container)) {
            Write-Log "  [X] GPO backup directory not found: $GPOBackupPath" -Level ERROR
            Write-Log "      Copy the GPO backup folders into that directory before running ImportSecurityHardeningGPOs." -Level ERROR
            $allOk = $false
        } else {
            Test-GPOBackups -BackupPath $GPOBackupPath | Out-Null
        }
    }

    if ($allOk) {
        Write-Log "`n[OK] All preflight checks passed`n" -Level SUCCESS
    } else {
        Write-Log "`n[X] Preflight checks failed. Aborting before any AD modification.`n" -Level ERROR
    }
    return $allOk
}

Export-ModuleMember -Function `
    Test-PSVersion, Test-RequiredModule, Test-AdminPrivileges, `
    Test-DomainConnectivity, Test-Configuration, Test-GPOBackups, `
    Invoke-PreflightChecks
