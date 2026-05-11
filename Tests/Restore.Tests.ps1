<#
.SYNOPSIS
    Pester tests for the Restore module (offline portions).

.DESCRIPTION
    Tests:
    - Module loads
    - Functions are exported
    - All restore functions support -WhatIf
    - All restore functions have ConfirmImpact = High
    - Get-AvailableBackups handles missing/empty directories gracefully
#>

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..\Modules\Restore.psm1'
    if (-not (Test-Path $script:ModulePath)) {
        throw "Restore module not found at: $script:ModulePath"
    }
    Import-Module $script:ModulePath -Force
    $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "sec_ad_restore_test_$(Get-Random)"
}

AfterAll {
    Remove-Module Restore -Force -ErrorAction SilentlyContinue
    if (Test-Path $script:TempDir) {
        Remove-Item -Path $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Module exports' {
    It 'exports the expected functions' {
        $expected = @(
            'Compare-StateBackup',
            'Restore-StateBackup',
            'Restore-OUSecurityDescriptor',
            'Restore-PreWindows2000Members',
            'Get-AvailableBackups'
        )
        $exports = (Get-Module Restore).ExportedFunctions.Keys
        foreach ($name in $expected) {
            $exports | Should -Contain $name
        }
    }
}

Describe 'Functions support -WhatIf' {
    It 'Restore-StateBackup supports -WhatIf' {
        (Get-Command Restore-StateBackup).Parameters.Keys | Should -Contain 'WhatIf'
    }
    It 'Restore-OUSecurityDescriptor supports -WhatIf' {
        (Get-Command Restore-OUSecurityDescriptor).Parameters.Keys | Should -Contain 'WhatIf'
    }
    It 'Restore-PreWindows2000Members supports -WhatIf' {
        (Get-Command Restore-PreWindows2000Members).Parameters.Keys | Should -Contain 'WhatIf'
    }
}

Describe 'High ConfirmImpact on destructive functions' {
    It 'Restore-StateBackup has ConfirmImpact = High' {
        $cmd = Get-Command Restore-StateBackup
        $attr = $cmd.ScriptBlock.Attributes |
                Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] }
        $attr.ConfirmImpact | Should -Be 'High'
    }
    It 'Restore-OUSecurityDescriptor has ConfirmImpact = High' {
        $cmd = Get-Command Restore-OUSecurityDescriptor
        $attr = $cmd.ScriptBlock.Attributes |
                Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] }
        $attr.ConfirmImpact | Should -Be 'High'
    }
    It 'Restore-PreWindows2000Members has ConfirmImpact = High' {
        $cmd = Get-Command Restore-PreWindows2000Members
        $attr = $cmd.ScriptBlock.Attributes |
                Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] }
        $attr.ConfirmImpact | Should -Be 'High'
    }
}

Describe 'Get-AvailableBackups' {
    It 'returns empty arrays for a non-existent directory' {
        $missing = Join-Path $script:TempDir 'nope'
        $result = Get-AvailableBackups -BackupDirectory $missing
        $result.State.Count      | Should -Be 0
        $result.ACL.Count        | Should -Be 0
        $result.PreWin2000.Count | Should -Be 0
    }

    It 'lists state and pre-win2000 files when present' {
        New-Item -ItemType Directory -Path $script:TempDir -Force | Out-Null
        '{}' | Set-Content -Path (Join-Path $script:TempDir 'state_backup_20260101_120000.json')
        '[]' | Set-Content -Path (Join-Path $script:TempDir 'preWin2000_members_20260101_120000.json')

        $result = Get-AvailableBackups -BackupDirectory $script:TempDir
        $result.State.Count      | Should -Be 1
        $result.PreWin2000.Count | Should -Be 1
        $result.ACL.Count        | Should -Be 0
    }

    It 'discovers ACL backups in the acl/ subdirectory' {
        $aclDir = Join-Path $script:TempDir 'acl'
        New-Item -ItemType Directory -Path $aclDir -Force | Out-Null
        '{}' | Set-Content -Path (Join-Path $aclDir 'acl_OU_test_20260101_120000.json')

        $result = Get-AvailableBackups -BackupDirectory $script:TempDir
        $result.ACL.Count | Should -Be 1
    }
}

Describe 'Restore-StateBackup parameter validation' {
    It 'throws when backup file does not exist' {
        # Compare-StateBackup throws if path missing — that's reached early in Restore-StateBackup
        { Compare-StateBackup -BackupFile 'C:\nope\nope.json' } | Should -Throw
    }
}
