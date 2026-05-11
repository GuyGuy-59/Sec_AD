<#
.SYNOPSIS
    Pester tests for the Logging module.
#>

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..\Modules\Logging.psm1'
    Import-Module $script:ModulePath -Force
    $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "sec_ad_test_$(Get-Random)"
}

AfterAll {
    if (Test-Path $script:TempDir) {
        Remove-Item -Path $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Module Logging -Force -ErrorAction SilentlyContinue
}

Describe 'Initialize-Logging' {
    It 'creates the log directory if missing' {
        $logFile = Initialize-Logging -LogDirectory $script:TempDir
        Test-Path $script:TempDir | Should -BeTrue
        Test-Path $logFile | Should -BeTrue
    }

    It 'returns a path with the timestamp pattern' {
        $logFile = Initialize-Logging -LogDirectory $script:TempDir
        $logFile | Should -Match 'sec_ad_\d{8}_\d{6}\.log$'
    }
}

Describe 'Write-Log' {
    BeforeAll {
        $script:logFile = Initialize-Logging -LogDirectory $script:TempDir
    }

    It 'writes to the log file' {
        Write-Log -Message 'Test message' -Level INFO -NoConsole
        $content = Get-Content $script:logFile -Raw
        $content | Should -Match '\[INFO\] Test message'
    }

    It 'respects level filtering (DEBUG hidden when level is INFO)' {
        Initialize-Logging -LogDirectory $script:TempDir -Level INFO | Out-Null
        $logFile = Get-LogFilePath
        Write-Log -Message 'Should not appear' -Level DEBUG -NoConsole
        $content = Get-Content $logFile -Raw
        $content | Should -Not -Match 'Should not appear'
    }

    It 'shows DEBUG when level is DEBUG' {
        Initialize-Logging -LogDirectory $script:TempDir -Level DEBUG | Out-Null
        $logFile = Get-LogFilePath
        Write-Log -Message 'Debug visible' -Level DEBUG -NoConsole
        $content = Get-Content $logFile -Raw
        $content | Should -Match 'Debug visible'
    }
}
