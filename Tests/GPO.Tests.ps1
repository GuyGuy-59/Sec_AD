<#
.SYNOPSIS
    Pester tests for the GPO module (offline / no AD required).

.DESCRIPTION
    Tests the pure logic functions that don't need AD connectivity:
    - Get-GPOsToImport
    - GUID validation regex
    - Configuration parsing
#>

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..\Modules\GPO.psm1'
    if (-not (Test-Path $script:ModulePath)) {
        throw "GPO module not found at: $script:ModulePath"
    }
    # Import the module so internal helpers are available via dot-sourcing
    # Get-GPOsToImport is internal; we re-source the module file in module scope.
    . $script:ModulePath -ErrorAction SilentlyContinue
}

Describe 'Get-GPOsToImport' {
    BeforeAll {
        $script:Config = [PSCustomObject]@{
            GPOs = [PSCustomObject]@{
                Common    = [PSCustomObject]@{ gpos = @('Common-A', 'Common-B') }
                Level2016 = [PSCustomObject]@{ gpos = @('Legacy-Win2016') }
                Level2025 = [PSCustomObject]@{ gpos = @('Modern-Win2025') }
            }
        }
    }

    It 'returns Common GPOs for any forest level' {
        $levels = @{ ForestLevel = 2019; DomainLevel = 2019 }
        $result = Get-GPOsToImport -FunctionalLevels $levels -GPOConfig $script:Config
        'Common-A' | Should -BeIn $result
        'Common-B' | Should -BeIn $result
    }

    It 'adds Level2016 GPOs when forest level is 2016' {
        $levels = @{ ForestLevel = 2016; DomainLevel = 2016 }
        $result = Get-GPOsToImport -FunctionalLevels $levels -GPOConfig $script:Config
        'Legacy-Win2016' | Should -BeIn $result
        'Modern-Win2025' | Should -Not -BeIn $result
    }

    It 'adds Level2025 GPOs when forest level is 2025+' {
        $levels = @{ ForestLevel = 2025; DomainLevel = 2025 }
        $result = Get-GPOsToImport -FunctionalLevels $levels -GPOConfig $script:Config
        'Modern-Win2025' | Should -BeIn $result
        'Legacy-Win2016' | Should -Not -BeIn $result
    }

    It 'returns only Common between 2017 and 2024' {
        $levels = @{ ForestLevel = 2019; DomainLevel = 2019 }
        $result = Get-GPOsToImport -FunctionalLevels $levels -GPOConfig $script:Config
        $result.Count | Should -Be 2
    }
}

Describe 'GPO backup folder GUID validation' {
    It 'matches valid GUIDs in {GUID} format' {
        $valid = @(
            '{02DE5552-EAA5-40A6-A2E1-A659C1DE57D0}',
            '{046E6EC2-1D63-4467-A766-DC936BBC3AF4}'
        )
        foreach ($name in $valid) {
            $name | Should -Match '^\{[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}$'
        }
    }

    It 'rejects malformed names' {
        $invalid = @('not-a-guid', '02DE5552-EAA5-40A6', '{ZZZZ5552-EAA5-40A6-A2E1-A659C1DE57D0}')
        foreach ($name in $invalid) {
            $name | Should -Not -Match '^\{[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}$'
        }
    }
}

Describe 'Resolve-TierSubOUMapping' {
    BeforeAll {
        $script:gpoModule = Join-Path $PSScriptRoot '..\Modules\GPO.psm1'
        Import-Module $script:gpoModule -Force
    }
    AfterAll {
        Remove-Module GPO -Force -ErrorAction SilentlyContinue
    }

    It 'parses granular subOUs format and builds correct DNs' {
        $mapping = [PSCustomObject]@{
            description = 'test'
            subOUs = [PSCustomObject]@{
                Workstations = [PSCustomObject]@{ gpos = @('GPO-A', 'GPO-B') }
                Users        = [PSCustomObject]@{ gpos = @('GPO-C') }
            }
        }
        $result = Resolve-TierSubOUMapping -TierMapping $mapping -TierName 'Tier2' -RootDN 'DC=lab,DC=local'

        $result.Count | Should -Be 2
        $ws = $result | Where-Object SubOUKey -EQ 'Workstations'
        $ws.OU       | Should -Be 'OU=Workstations,OU=_Tier2,DC=lab,DC=local'
        $ws.GPOs     | Should -Be @('GPO-A', 'GPO-B')
        $ws.IsRoot   | Should -BeFalse
    }

    It 'falls back to legacy flat format when subOUs is missing' {
        $mapping = [PSCustomObject]@{
            description = 'legacy'
            gpos = @('Legacy-GPO-1', 'Legacy-GPO-2')
        }
        $result = Resolve-TierSubOUMapping -TierMapping $mapping -TierName 'Tier1' -RootDN 'DC=lab,DC=local'

        $result.Count | Should -Be 1
        $result[0].OU     | Should -Be 'OU=_Tier1,DC=lab,DC=local'
        $result[0].IsRoot | Should -BeTrue
        $result[0].GPOs.Count | Should -Be 2
    }

    It 'handles _root as a special key linking to the tier OU itself' {
        $mapping = [PSCustomObject]@{
            subOUs = [PSCustomObject]@{
                _root  = [PSCustomObject]@{ gpos = @('Tier-Wide-GPO') }
                Admins = [PSCustomObject]@{ gpos = @('Admin-GPO') }
            }
        }
        $result = Resolve-TierSubOUMapping -TierMapping $mapping -TierName 'Tier0' -RootDN 'DC=lab,DC=local'

        $rootEntry = $result | Where-Object IsRoot -EQ $true
        $rootEntry.OU | Should -Be 'OU=_Tier0,DC=lab,DC=local'

        $adminEntry = $result | Where-Object SubOUKey -EQ 'Admins'
        $adminEntry.OU | Should -Be 'OU=Admins,OU=_Tier0,DC=lab,DC=local'
    }

    It 'skips sub-OUs with empty gpos arrays' {
        $mapping = [PSCustomObject]@{
            subOUs = [PSCustomObject]@{
                Empty   = [PSCustomObject]@{ gpos = @() }
                Servers = [PSCustomObject]@{ gpos = @('Server-GPO') }
            }
        }
        $result = Resolve-TierSubOUMapping -TierMapping $mapping -TierName 'Tier1' -RootDN 'DC=lab,DC=local'
        $result.Count | Should -Be 1
        $result[0].SubOUKey | Should -Be 'Servers'
    }

    It 'returns empty when no gpos and no subOUs' {
        $mapping = [PSCustomObject]@{ description = 'empty' }
        $result = Resolve-TierSubOUMapping -TierMapping $mapping -TierName 'Tier2' -RootDN 'DC=lab,DC=local'
        $result.Count | Should -Be 0
    }
}
