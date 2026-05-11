<#
.SYNOPSIS
    Creates (or updates) a GPO that configures Microsoft Defender Attack Surface Reduction (ASR) rules.

.DESCRIPTION
    This script provisions a Group Policy Object that enforces a recommended baseline of ASR rules.
    Best practice is to deploy ASR in Audit mode first (to identify false positives), then switch to Block.

.PARAMETER GpoName
    Name of the GPO to create / update. Default: "Defender-ASR".

.PARAMETER Mode
    ASR enforcement mode:
        - Block (1)  : Block the behavior (recommended for production after audit phase).
        - Audit (2)  : Log only, do not block (recommended for initial rollout).
        - Warn  (6)  : Warn the user but allow the action.
        - Off   (0)  : Disable the rule.
    Default: Audit.

.PARAMETER Domain
    Target domain. Defaults to the current user's domain.

.EXAMPLE
    .\Generator-GPO-ASR.ps1 -Mode Audit
    Create the GPO in Audit mode (safe for initial deployment).

.EXAMPLE
    .\Generator-GPO-ASR.ps1 -Mode Block
    Switch the GPO to Block mode after audit phase validation.

.NOTES
    Reference: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string]$GpoName = "Defender-ASR",

    [Parameter()]
    [ValidateSet("Off", "Block", "Audit", "Warn")]
    [string]$Mode = "Audit",

    [Parameter()]
    [string]$Domain
)

Import-Module GroupPolicy -ErrorAction Stop

# Map friendly mode to ASR numeric value
$modeValue = switch ($Mode) {
    "Off"   { 0 }
    "Block" { 1 }
    "Audit" { 2 }
    "Warn"  { 6 }
}

# Registry paths for ASR settings
$asrRegPath   = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
$asrRulesPath = "$asrRegPath\Rules"

# ASR rule GUIDs (https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
$asrRules = [ordered]@{
    "56A863A9-875E-4185-98A7-B882C64B5CE5" = "Block abuse of exploited vulnerable signed drivers"
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = "Block Adobe Reader from creating child processes"
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office applications from creating child processes"
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from LSASS"
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email and webmail"
    "01443614-CD74-433A-B99E-2ECDC07BFC25" = "Block executable files unless they meet prevalence/age/trust criteria"
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
    "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JS/VBS from launching downloaded executable content"
    "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content"
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office applications from injecting code into other processes"
    "26190899-1602-49E8-8B27-EB1D0A1CE869" = "Block Office communication app from creating child processes"
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block persistence through WMI event subscription"
    "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block process creations from PSExec/WMI commands"
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = "Block untrusted/unsigned processes from USB"
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
    "C1DB55AB-C21A-4637-BB3F-A12568109D35" = "Use advanced protection against ransomware"
    "A8F5898E-1DC8-49A9-9878-85004B8A61E6" = "Block Webshell creation for Servers"
    "33DDEDF1-C6E0-47CB-833E-DE6133960387" = "Block rebooting machine in Safe Mode"
    "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB" = "Block use of copied or impersonated system tools"
}

Write-Host "`n=== Configuring ASR GPO ===" -ForegroundColor Cyan
Write-Host "GPO Name : $GpoName" -ForegroundColor Yellow
Write-Host "Mode     : $Mode (value: $modeValue)" -ForegroundColor Yellow
Write-Host "Rules    : $($asrRules.Count)" -ForegroundColor Yellow

# Get-or-create GPO (idempotent)
$gpoParams = @{ Name = $GpoName; ErrorAction = 'SilentlyContinue' }
if ($Domain) { $gpoParams.Domain = $Domain }
$gpo = Get-GPO @gpoParams

if (-not $gpo) {
    Write-Host "`n-> GPO not found, creating..." -ForegroundColor Yellow
    if ($PSCmdlet.ShouldProcess($GpoName, "Create GPO")) {
        $createParams = @{
            Name    = $GpoName
            Comment = "ASR rules baseline ($Mode mode). Managed by Generator-GPO-ASR.ps1."
        }
        if ($Domain) { $createParams.Domain = $Domain }
        $gpo = New-GPO @createParams
        Write-Host "  [OK] GPO created" -ForegroundColor Green
    }
} else {
    Write-Host "`n-> GPO already exists, updating settings..." -ForegroundColor Yellow
}

# Enable the ASR feature itself
if ($PSCmdlet.ShouldProcess($GpoName, "Enable ASR feature")) {
    Set-GPRegistryValue -Name $GpoName -Key $asrRegPath `
        -ValueName "ExploitGuard_ASR_Rules" -Type DWord -Value 1 | Out-Null
    Write-Host "  [OK] ASR feature enabled" -ForegroundColor Green
}

# Apply each ASR rule
Write-Host "`n-> Applying ASR rules..." -ForegroundColor Yellow
$success = 0
$failed  = 0
foreach ($rule in $asrRules.GetEnumerator()) {
    $guid = $rule.Key
    $desc = $rule.Value
    try {
        if ($PSCmdlet.ShouldProcess("$GpoName : $guid", "Set ASR rule '$desc' to $Mode")) {
            Set-GPRegistryValue -Name $GpoName -Key $asrRulesPath `
                -ValueName $guid -Type DWord -Value $modeValue -ErrorAction Stop | Out-Null
            Write-Host "  [OK] $desc" -ForegroundColor Green
            $success++
        }
    } catch {
        Write-Warning "  [X] Failed to set rule $guid ($desc): $($_.Exception.Message)"
        $failed++
    }
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "  Applied : $success" -ForegroundColor Green
if ($failed -gt 0) { Write-Host "  Failed  : $failed" -ForegroundColor Red }
Write-Host "`n[!] Reminder:" -ForegroundColor Yellow
Write-Host "    - Link this GPO to the appropriate OU(s) (Tier0/1/2)." -ForegroundColor Yellow
Write-Host "    - Start in Audit mode, monitor Defender events (1121/1122/5007)," -ForegroundColor Yellow
Write-Host "      then re-run with -Mode Block once exclusions are tuned." -ForegroundColor Yellow
