<#
.SYNOPSIS
    Centralized logging for the Sec_AD project.

.DESCRIPTION
    Provides Write-Log with severity levels (DEBUG/INFO/WARN/ERROR/SUCCESS) and dual output
    (console with colors + log file). Logs are rotated by execution timestamp.
    Console output preserves the original Write-Host visual contract used across the project.
#>

$script:LogFilePath = $null
$script:LogLevel    = 'INFO'

$script:LevelOrder = @{
    DEBUG   = 0
    INFO    = 1
    SUCCESS = 1
    WARN    = 2
    ERROR   = 3
}

$script:LevelColor = @{
    DEBUG   = 'Gray'
    INFO    = 'White'
    SUCCESS = 'Green'
    WARN    = 'Yellow'
    ERROR   = 'Red'
}

function Initialize-Logging {
    <#
    .SYNOPSIS Initialize the log file for this run.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogDirectory,

        [Parameter()]
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO',

        [Parameter()]
        [string]$Prefix = 'sec_ad'
    )

    if (-not (Test-Path $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force -WhatIf:$false -Confirm:$false | Out-Null
    }

    $timestamp           = Get-Date -Format 'yyyyMMdd_HHmmss'
    $script:LogFilePath  = Join-Path $LogDirectory "${Prefix}_${timestamp}.log"
    $script:LogLevel     = $Level

    $header = @(
        "========================================================================",
        " Sec_AD execution log",
        " Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        " User    : $env:USERDOMAIN\$env:USERNAME",
        " Host    : $env:COMPUTERNAME",
        " PSVersion: $($PSVersionTable.PSVersion)",
        "========================================================================"
    ) -join "`n"
    Set-Content -Path $script:LogFilePath -Value $header -Encoding UTF8 -WhatIf:$false -Confirm:$false

    Write-Host "Log file: $script:LogFilePath" -ForegroundColor Cyan
    return $script:LogFilePath
}

function Write-Log {
    <#
    .SYNOPSIS Write a message to console and log file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO',

        [Parameter()]
        [switch]$NoConsole,

        [Parameter()]
        [switch]$NoFile,

        [Parameter()]
        [ConsoleColor]$Color
    )

    # Filter by configured level
    $minOrder     = $script:LevelOrder[$script:LogLevel]
    $messageOrder = $script:LevelOrder[$Level]
    if ($messageOrder -lt $minOrder) { return }

    # Console
    if (-not $NoConsole) {
        $consoleColor = if ($PSBoundParameters.ContainsKey('Color')) { $Color } else { $script:LevelColor[$Level] }
        Write-Host $Message -ForegroundColor $consoleColor
    }

    # File
    if (-not $NoFile -and $script:LogFilePath) {
        $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $line  = "[$stamp] [$Level] $Message"
        try {
            Add-Content -Path $script:LogFilePath -Value $line -Encoding UTF8 -ErrorAction Stop -WhatIf:$false -Confirm:$false
        } catch {
            # Don't crash the run if logging fails
            Write-Host "[!] Failed to write to log file: $_" -ForegroundColor Magenta
        }
    }
}

function Get-LogFilePath {
    return $script:LogFilePath
}

Export-ModuleMember -Function Initialize-Logging, Write-Log, Get-LogFilePath
