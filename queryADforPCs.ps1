# Try to import the Active Directory module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host "Error: Unable to load the Active Directory module. This script must be run on a system where the Active Directory module is installed, typically a Domain Controller." -ForegroundColor Red
    exit
}

# Define the target organizational unit (OU) to search within
$TargetOU = "OU=Computers,OU=MyBusiness,DC=MyDomain,DC=com"

# Try to get the computer accounts from the target OU
try {
    $Computers = Get-ADComputer -Filter * -SearchBase $TargetOU -ErrorAction Stop | Select-Object -ExpandProperty Name
} catch {
    Write-Host "Error: Unable to retrieve computer accounts. Please ensure this script is run with appropriate permissions and the specified OU is correct." -ForegroundColor Red
    exit
}

# Specify the path to save the list
$OutputPath = "\\path\to\shared\folder\targets.txt"

# Try to save the list to the targets file
try {
    $Computers | Out-File -FilePath $OutputPath -ErrorAction Stop
} catch {
    Write-Host "Error: Unable to save the list to the network path. Please ensure the network path is accessible and the current user has write permissions." -ForegroundColor Red
    exit
}

Write-Host "List of target PCs saved to $OutputPath" -ForegroundColor Green
