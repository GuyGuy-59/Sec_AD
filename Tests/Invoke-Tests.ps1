<#
.SYNOPSIS
    Runs all offline Pester tests for the Sec_AD project.

.DESCRIPTION
    Executes tests that don't require AD connectivity. Outputs a summary suitable for CI.

.EXAMPLE
    .\Tests\Invoke-Tests.ps1

.EXAMPLE
    .\Tests\Invoke-Tests.ps1 -CI
    Run with NUnit XML output for CI integration.
#>
[CmdletBinding()]
param(
    [switch]$CI
)

# Ensure Pester 5+
$pester = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester -or $pester.Version.Major -lt 5) {
    Write-Host "Installing Pester 5+..." -ForegroundColor Yellow
    Install-Module -Name Pester -MinimumVersion 5.0.0 -Force -SkipPublisherCheck -Scope CurrentUser
}
Import-Module Pester -MinimumVersion 5.0.0

$config = New-PesterConfiguration
$config.Run.Path           = $PSScriptRoot
$config.Output.Verbosity   = 'Detailed'
$config.Run.PassThru       = $true

if ($CI) {
    $config.TestResult.Enabled      = $true
    $config.TestResult.OutputPath   = Join-Path $PSScriptRoot 'TestResults.xml'
    $config.TestResult.OutputFormat = 'NUnitXml'
}

$result = Invoke-Pester -Configuration $config

Write-Host "`n=== Test Summary ===" -ForegroundColor Cyan
Write-Host "Passed : $($result.PassedCount)" -ForegroundColor Green
Write-Host "Failed : $($result.FailedCount)" -ForegroundColor $(if ($result.FailedCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "Skipped: $($result.SkippedCount)" -ForegroundColor Yellow

if ($result.FailedCount -gt 0) { exit 1 }
exit 0
