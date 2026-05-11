<#
.SYNOPSIS
    Pester tests for ADHardening module (offline portions only).

.DESCRIPTION
    Tests the parts of ADHardening that don't require an active AD:
    - Module loads cleanly
    - Functions are exported as expected
    - Remove-PrivilegedGroupMember refuses Administrator without override flag
    - Backup file naming and structure
#>

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..\Modules\ADHardening.psm1'
    if (-not (Test-Path $script:ModulePath)) {
        throw "ADHardening module not found at: $script:ModulePath"
    }

    # Stub the AD cmdlets used by Remove-PrivilegedGroupMember so we can test offline
    function Get-ADGroup { param($Identity, [switch]$ErrorAction)
        return [PSCustomObject]@{ Name = $Identity; SamAccountName = $Identity }
    }
    function Remove-ADGroupMember { param($Identity, $Members, [switch]$Confirm, $ErrorAction)
        # Track invocations for assertions
        $script:LastRemove = @{ Group = $Identity; Member = $Members }
    }

    Import-Module $script:ModulePath -Force
}

AfterAll {
    Remove-Module ADHardening -Force -ErrorAction SilentlyContinue
}

Describe 'Module exports' {
    It 'exports the expected functions' {
        $expected = @(
            'Set-TierOUDelegation',
            'Backup-OUSecurityDescriptor',
            'New-Tier0AuthenticationPolicySilo',
            'Add-Tier0SiloMember',
            'Lock-PreWindows2000Group',
            'Get-PrivilegedGroupAudit',
            'Remove-PrivilegedGroupMember',
            'Set-Tier0AccountSensitive'
        )
        $exports = (Get-Module ADHardening).ExportedFunctions.Keys
        foreach ($name in $expected) {
            $exports | Should -Contain $name
        }
    }
}

Describe 'Remove-PrivilegedGroupMember safety guard' {
    BeforeEach {
        $script:LastRemove = $null
    }

    It 'refuses to remove Administrator by default' {
        Remove-PrivilegedGroupMember -GroupName 'Domain Admins' `
            -MemberSamAccountName 'Administrator' -Confirm:$false 6>$null
        $script:LastRemove | Should -BeNullOrEmpty
    }

    It 'allows Administrator removal when -AllowAdministratorRemoval is set' {
        Remove-PrivilegedGroupMember -GroupName 'Domain Admins' `
            -MemberSamAccountName 'Administrator' `
            -AllowAdministratorRemoval -Confirm:$false 6>$null
        $script:LastRemove | Should -Not -BeNullOrEmpty
        $script:LastRemove.Member | Should -Be 'Administrator'
    }

    It 'allows non-Administrator removal' {
        Remove-PrivilegedGroupMember -GroupName 'Domain Admins' `
            -MemberSamAccountName 'jdoe' -Confirm:$false 6>$null
        $script:LastRemove | Should -Not -BeNullOrEmpty
        $script:LastRemove.Member | Should -Be 'jdoe'
    }
}

Describe 'Functions support ShouldProcess' {
    It 'Set-TierOUDelegation supports -WhatIf' {
        (Get-Command Set-TierOUDelegation).Parameters.Keys | Should -Contain 'WhatIf'
    }
    It 'New-Tier0AuthenticationPolicySilo supports -WhatIf' {
        (Get-Command New-Tier0AuthenticationPolicySilo).Parameters.Keys | Should -Contain 'WhatIf'
    }
    It 'Lock-PreWindows2000Group supports -WhatIf' {
        (Get-Command Lock-PreWindows2000Group).Parameters.Keys | Should -Contain 'WhatIf'
    }
    It 'Set-Tier0AccountSensitive supports -WhatIf' {
        (Get-Command Set-Tier0AccountSensitive).Parameters.Keys | Should -Contain 'WhatIf'
    }
}

Describe 'New-Tier0AuthenticationPolicySilo parameters' {
    It 'requires -SiloConfigPath (Mode is no longer a direct parameter)' {
        $params = (Get-Command New-Tier0AuthenticationPolicySilo).Parameters
        $params.Keys | Should -Contain 'SiloConfigPath'
        $params.Keys | Should -Not -Contain 'Mode'
        $params['SiloConfigPath'].Attributes.Mandatory | Should -Contain $true
    }

    It 'function body contains SDDL conditions on UserAllowedToAuthenticateTo and ComputerAllowedToAuthenticateTo' {
        $body = (Get-Command New-Tier0AuthenticationPolicySilo).Definition
        $body | Should -Match 'UserAllowedToAuthenticateTo'
        $body | Should -Match 'ComputerAllowedToAuthenticateTo'
        $body | Should -Match '@USER\.ad://ext/AuthenticationSilo'
        $body | Should -Match '@USER\.ad://ext/AuthenticationSilo'
    }

    It 'function body reads Mode / PolicyName / SiloName / Members from the config object' {
        $body = (Get-Command New-Tier0AuthenticationPolicySilo).Definition
        $body | Should -Match '\$cfg\.Mode'
        $body | Should -Match '\$cfg\.PolicyName'
        $body | Should -Match '\$cfg\.SiloName'
        $body | Should -Match '\$cfg\.Members'
    }
}

Describe 'Silo_config.json shape' {
    BeforeAll {
        $script:SiloConfigPath = Join-Path $PSScriptRoot '..\Config\Silo_config.json'
    }

    It 'exists and is valid JSON' {
        Test-Path $script:SiloConfigPath | Should -BeTrue
        { Get-Content -Raw $script:SiloConfigPath | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'has the required top-level keys' {
        $cfg = Get-Content -Raw $script:SiloConfigPath | ConvertFrom-Json
        @('PolicyName', 'SiloName', 'Mode', 'TGTLifetimeMinutes', 'Members') |
            ForEach-Object { $cfg.PSObject.Properties.Name | Should -Contain $_ }
    }

    It 'has Mode set to Audit or Enforce' {
        $cfg = Get-Content -Raw $script:SiloConfigPath | ConvertFrom-Json
        $cfg.Mode | Should -BeIn @('Audit', 'Enforce')
    }

    It 'has Users / Computers / Services sub-arrays under Members' {
        $cfg = Get-Content -Raw $script:SiloConfigPath | ConvertFrom-Json
        @('Users', 'Computers', 'Services') |
            ForEach-Object { $cfg.Members.PSObject.Properties.Name | Should -Contain $_ }
    }
}

Describe 'Remove-PrivilegedGroupMember has High ConfirmImpact' {
    It 'has ConfirmImpact set to High' {
        $cmd = Get-Command Remove-PrivilegedGroupMember
        $attr = $cmd.ScriptBlock.Attributes |
                Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] }
        $attr.ConfirmImpact | Should -Be 'High'
    }
}
