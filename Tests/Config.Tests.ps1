<#
.SYNOPSIS
    Pester tests for configuration files structure.
#>

BeforeAll {
    $script:RepoRoot       = Join-Path $PSScriptRoot '..'
    $script:GlobalConfig   = Join-Path $script:RepoRoot 'Config\Global_config.json'
    $script:GpoConfig      = Join-Path $script:RepoRoot 'Config\GPO_config.json'
}

Describe 'Global_config.json structure' {
    BeforeAll {
        $script:cfg = Get-Content -Path $script:GlobalConfig -Raw | ConvertFrom-Json
    }

    It 'is valid JSON' {
        { Get-Content -Path $script:GlobalConfig -Raw | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'has required top-level keys' {
        @('RootDN', 'AdmName', 'TierNames', 'TargetDomain', 'GPOBackupPath', 'Functions') |
            ForEach-Object { $script:cfg.PSObject.Properties.Name | Should -Contain $_ }
    }

    It 'RootDN is in DC=...,DC=... format' {
        $script:cfg.RootDN | Should -Match '^(DC=[^,]+)(,DC=[^,]+)+$'
    }

    It 'TargetDomain is a FQDN' {
        $script:cfg.TargetDomain | Should -Match '^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$'
    }

    It 'TierNames is non-empty array' {
        $script:cfg.TierNames.Count | Should -BeGreaterThan 0
    }

    It 'all Functions values are booleans' {
        foreach ($prop in $script:cfg.Functions.PSObject.Properties) {
            $prop.Value | Should -BeOfType [bool]
        }
    }
}

Describe 'GPO_config.json structure' {
    BeforeAll {
        $script:gcfg = Get-Content -Path $script:GpoConfig -Raw | ConvertFrom-Json
    }

    It 'is valid JSON' {
        { Get-Content -Path $script:GpoConfig -Raw | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'has GPOs.Common section' {
        $script:gcfg.GPOs.Common.gpos.Count | Should -BeGreaterThan 0
    }

    It 'TierMappings tiers reference GPOs from the catalog' {
        $catalog = @($script:gcfg.GPOs.Common.gpos) +
                   @($script:gcfg.GPOs.Level2016.gpos) +
                   @($script:gcfg.GPOs.Level2025.gpos)
        foreach ($tierName in $script:gcfg.TierMappings.PSObject.Properties.Name) {
            $tier = $script:gcfg.TierMappings.$tierName
            $tierRefs = @()
            if ($tier.PSObject.Properties.Name -contains 'subOUs' -and $tier.subOUs) {
                foreach ($prop in $tier.subOUs.PSObject.Properties) {
                    if ($prop.Value.gpos) { $tierRefs += $prop.Value.gpos }
                }
            } elseif ($tier.gpos) {
                $tierRefs = $tier.gpos
            }
            foreach ($gpo in $tierRefs) {
                $catalog | Should -Contain $gpo -Because "Tier $tierName references GPO '$gpo' which must exist in the catalog"
            }
        }
    }

    It 'has no duplicate GPOs within the same OU mapping' {
        foreach ($tierName in $script:gcfg.TierMappings.PSObject.Properties.Name) {
            $tier = $script:gcfg.TierMappings.$tierName
            if ($tier.PSObject.Properties.Name -contains 'subOUs' -and $tier.subOUs) {
                foreach ($prop in $tier.subOUs.PSObject.Properties) {
                    $gpos = $prop.Value.gpos
                    if ($gpos) {
                        $unique = $gpos | Select-Object -Unique
                        $gpos.Count | Should -Be $unique.Count -Because "${tierName}\$($prop.Name) should not list the same GPO twice"
                    }
                }
            } elseif ($tier.gpos) {
                $unique = $tier.gpos | Select-Object -Unique
                $tier.gpos.Count | Should -Be $unique.Count -Because "Tier $tierName should not list the same GPO twice"
            }
        }
    }
}

Describe 'GPO backup folders match catalog' {
    BeforeAll {
        $script:gpoDir = Join-Path $script:RepoRoot 'GPO'
        $script:gcfg = Get-Content -Path $script:GpoConfig -Raw | ConvertFrom-Json
        $script:catalog = @($script:gcfg.GPOs.Common.gpos) +
                          @($script:gcfg.GPOs.Level2016.gpos) +
                          @($script:gcfg.GPOs.Level2025.gpos)
    }

    It 'GPO directory exists' {
        Test-Path $script:gpoDir | Should -BeTrue
    }

    It 'every catalog GPO has a backup folder with gpreport.xml' {
        $foundGpos = @()
        Get-ChildItem -Path $script:gpoDir -Directory | Where-Object {
            $_.Name -match '^\{[0-9a-fA-F\-]{36}\}$'
        } | ForEach-Object {
            $report = Join-Path $_.FullName 'gpreport.xml'
            if (Test-Path $report) {
                try {
                    [xml]$xml = Get-Content $report
                    $foundGpos += $xml.GPO.Name
                } catch { }
            }
        }
        $missing = $script:catalog | Where-Object { $_ -notin $foundGpos }
        $missing | Should -BeNullOrEmpty -Because "Every configured GPO must have a backup: missing => $($missing -join ', ')"
    }
}
