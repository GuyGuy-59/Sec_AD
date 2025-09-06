function New-OU {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ParentDN,
        
        [Parameter(Mandatory=$true)]
        [string]$OUName
    )
    
    try {
        Write-Host "`n-> Creating OU: $OUName" -ForegroundColor Yellow
        Write-Host "  Parent DN: $ParentDN" -ForegroundColor Gray
        
        $OUPath = "OU=$OUName,$ParentDN"
        
        if (-not (Get-ADOrganizationalUnit -Filter {Name -eq $OUName} -SearchBase $ParentDN -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name $OUName -Path $ParentDN -ErrorAction Stop
            Write-Host "  [OK] OU created successfully" -ForegroundColor Green
        } else {
            Write-Host "  [OK] OU already exists" -ForegroundColor Yellow
        }
        
        return $OUPath
    }
    catch {
        Write-Error "[X] Failed to create OU '$OUName': $_"
        throw
    }
}

function New-Group {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("DomainLocal", "Global", "Universal")]
        [string]$GroupScope,
        
        [Parameter(Mandatory=$true)]
        [string]$ParentOU
    )
    
    try {
        Write-Host "`n-> Creating Group: $GroupName" -ForegroundColor Yellow
        Write-Host "  Parent OU: $ParentOU" -ForegroundColor Gray
        
        if (-not (Get-ADGroup -Filter {Name -eq $GroupName} -SearchBase $ParentOU -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name $GroupName -GroupScope $GroupScope -Path $ParentOU -GroupCategory Security -ErrorAction Stop
            Write-Host "  [OK] Group created successfully" -ForegroundColor Green
        } else {
            Write-Host "  [OK] Group already exists" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "[X] Failed to create group '$GroupName': $_"
        throw
    }
}

# Explicitly export the functions
Export-ModuleMember -Function New-OU, New-Group 