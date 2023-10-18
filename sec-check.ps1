# Ensure the script runs with elevated privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    Break
}

# Get the device name
$deviceName = $env:COMPUTERNAME

# Define the path for the output file in the script directory including the device name
$outputFile = Join-Path $PSScriptRoot "Security_Report_$deviceName.txt"


# Uncomment the line below and update "YOUR_NETWORK_PATH" to save the report to a network location
# Make sure that the network location is accessible and the appropriate permissions are set for writing to the directory.
# $outputFile = "\\YOUR_NETWORK_PATH\Security_Report_$deviceName.txt"

# Function to write output to the text file
function Write-OutputToFile ($Message) {
    Write-Output $Message | Out-File -FilePath $outputFile -Append -Encoding UTF8
}

# Function to write a warning message to the text file
function Write-WarningToFile ($Message) {
    Write-Warning $Message | Out-File -FilePath $outputFile -Append -Encoding UTF8
}

# Clear the content of the report file if it exists or create a new one
if (Test-Path $outputFile) {
    Clear-Content $outputFile
} else {
    New-Item -Path $outputFile -ItemType File
}

# Start of the report
Write-OutputToFile "----- Windows 11 Security Status Report for $deviceName -----`n"

# Windows Firewall Status
$firewallProfile = (Get-NetFirewallProfile -PolicyStore ActiveStore).Where({ $_.Enabled -eq $true }).Name
if($firewallProfile) {
    Write-OutputToFile "Windows Firewall is ENABLED for profiles: $firewallProfile"
} else {
    Write-OutputToFile "WARNING: Windows Firewall is DISABLED. :WARNING"
}

# UAC Status
$UAC = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name "EnableLUA"
if($UAC.EnableLUA -eq 1) {
    Write-OutputToFile "`nUser Account Control (UAC) is ENABLED."
} else {
    Write-OutputToFile "`nWARNING: User Account Control (UAC) is DISABLED. :WARNING"
}

# Windows Defender Status
$defenderStatus = Get-MpComputerStatus
if($defenderStatus.AntivirusEnabled) {
    Write-OutputToFile "`nWindows Defender Antivirus is ENABLED."
} else {
    Write-OutputToFile "`nWARNING: Windows Defender Antivirus is DISABLED. :WARNING"
}

# BitLocker Status
$bitLockerStatus = Get-BitLockerVolume | Where-Object { $_.MountPoint -eq "C:" }
if($bitLockerStatus.ProtectionStatus -eq "On") {
    Write-OutputToFile "`nBitLocker is ENABLED for C: drive."
} else {
    Write-OutputToFile "`nWARNING: BitLocker is DISABLED or NOT ACTIVE for C: drive. :WARNING"
}

# Function to write output to the text file
function Write-OutputToFile ($Message) {
    Write-Output $Message | Out-File -FilePath $outputFile -Append -Encoding UTF8
}

# Define a function to check for updates
function Check-ForUpdates {
    # Access the Windows Update Agent API
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

    # Search for pending updates
    Write-OutputToFile "`nChecking for available updates..."
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0")

    # List the updates
    if ($SearchResult.Updates.Count -eq 0) {
        Write-OutputToFile "Your system is up to date. No pending updates found."
    } else {
        Write-OutputToFile "Updates available: $($SearchResult.Updates.Count)"
        foreach ($Update in $SearchResult.Updates) {
            Write-OutputToFile "Title: $($Update.Title)"
        }
    }
}

# Run the function to check for updates
Check-ForUpdates

# Function to write output to the text file
function Write-OutputToFile ($Message) {
    Write-Output $Message | Out-File -FilePath $outputFile -Append -Encoding UTF8
}

# Define a function to check the password policy
function Check-PasswordPolicy {
    Write-OutputToFile "`nChecking the system's password policy..."

    try {
        # Run 'net accounts' and capture its output
        $netAccountsOutput = net accounts

        # Parse the output for relevant policy information
        $passwordPolicy = $netAccountsOutput -match 'Minimum password|Maximum password|Minimum password age|Maximum password age|The system will lock|password history|The command completed'

        # Write the policy information to the output file
        if ($passwordPolicy) {
            $passwordPolicy | ForEach-Object {
                Write-OutputToFile $_.ToString()
            }
        } else {
            Write-OutputToFile "No password policy details could be retrieved."
        }
    } catch {
        Write-OutputToFile "An error occurred while checking the password policy."
    }
}

# Run the function to check the password policy
Check-PasswordPolicy

# Function to write output to the text file
function Write-OutputToFile ($Message) {
    Write-Output $Message | Out-File -FilePath $outputFile -Append -Encoding UTF8
}

function Check-FailedLogins {
    Write-OutputToFile "`nChecking for recent failed login attempts..."

    try {
        # Query the event log for the last 7 days
        $startDate = (Get-Date).AddDays(-7)
        $eventLogQuery = @{LogName='Security'; Id=4625; StartTime=$startDate}
        
        # Check if there are any events that match the criteria
        if (Get-WinEvent -FilterHashtable $eventLogQuery -ErrorAction SilentlyContinue) {
            $failedLogins = Get-WinEvent -FilterHashtable $eventLogQuery
            Write-OutputToFile "Recent failed login attempts found: $($failedLogins.Count)"
            # Limiting the number of details printed to the last 5 failed logins for brevity
            $failedLogins | Select-Object -First 5 | ForEach-Object {
                $eventXml = [xml]$_.ToXml()
                $targetUserName = $eventXml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
                $logonType = $eventXml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'} | Select-Object -ExpandProperty '#text'
                $ipAddress = $eventXml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
                Write-OutputToFile "Failed login for user: $targetUserName, Logon Type: $logonType, from IP: $ipAddress"
            }
        } else {
            Write-OutputToFile "No recent failed login attempts found."
        }
    } catch {
        Write-OutputToFile "An error occurred while checking for failed login attempts."
    }
}

# Run the function to check for failed login attempts
Check-FailedLogins

# check local accounts with admin privledges, note if disabled.
function Check-LocalAdminAccounts {
    Write-OutputToFile "`nChecking for local administrative accounts..."

    try {
        # Get the local Administrators group
        $administratorsGroup = Get-LocalGroup -Name "Administrators"
        
        # Get members of the Administrators group
        $adminAccounts = Get-LocalGroupMember -Group $administratorsGroup

        if ($adminAccounts) {
            Write-OutputToFile "Local administrative accounts found: $($adminAccounts.Count)"
            foreach ($account in $adminAccounts) {
                # Check if the account is a local one and if it's disabled
                if ($account.ObjectClass -eq 'User') {
                    $localUser = Get-LocalUser -Name $account.Name.Split("\")[-1]
                    if ($localUser.Enabled) {
                        Write-OutputToFile "Account Name: $($account.Name) - Account Type: $($account.PrincipalSource) - Status: Enabled"
                    } else {
                        Write-OutputToFile "Account Name: $($account.Name) - Account Type: $($account.PrincipalSource) - Status: Disabled"
                    }
                } else {
                    # If not a user (e.g., a group), just list it out
                    Write-OutputToFile "Account Name: $($account.Name) - Account Type: $($account.PrincipalSource)"
                }
            }
        } else {
            Write-OutputToFile "No local administrative accounts found."
        }
    } catch {
        Write-OutputToFile "An error occurred while checking for local administrative accounts."
    }
}

# Run the function to check for local administrative accounts
Check-LocalAdminAccounts

# Function to check for the Guest account and its status
function Check-GuestAccountStatus {
    Write-OutputToFile "`nChecking the status of the local Guest account..."

    try {
        # Try to get the Guest account
        $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue

        if ($null -ne $guestAccount) {
            if ($guestAccount.Enabled) {
                Write-OutputToFile "WARNING: The local Guest account is ENABLED. :WARNING"
            } else {
                Write-OutputToFile "The local Guest account is present but disabled."
            }
        } else {
            Write-OutputToFile "No local Guest account present."
        }
    } catch {
        Write-OutputToFile "An error occurred while checking the local Guest account status."
    }
}

# Run the function to check the Guest account status
Check-GuestAccountStatus

# Function to list all network shares
function List-NetworkShares {
    Write-OutputToFile "`nListing all network shares..."

    try {
        # Get all network shares
        $shares = Get-SmbShare -Special $false  # Excluding default system shares

        if ($shares) {
            Write-OutputToFile "Network Shares:"
            foreach ($share in $shares) {
                Write-OutputToFile "Name: $($share.Name) - Path: $($share.Path) - Description: $($share.Description)"
            }
        } else {
            Write-OutputToFile "No network shares found."
        }
    } catch {
        Write-OutputToFile "An error occurred while listing network shares."
    }
}

# Run the function to list network shares
List-NetworkShares

# Function to check AutoRun status
function Check-AutoRunStatus {
    Write-OutputToFile "`nChecking AutoRun status..."

    try {
        # Query the registry value for AutoRun
        $autoRunValue = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue

        # The value 0xFF disables AutoRun on all types of drives
        if ($null -ne $autoRunValue -and $autoRunValue.NoDriveTypeAutoRun -eq 0xFF) {
            Write-OutputToFile "AutoRun is DISABLED for all drives."
        } else {
            Write-OutputToFile "WARNING: AutoRun is NOT disabled for all drives. :WARNING"
        }
    } catch {
        Write-OutputToFile "An error occurred while checking AutoRun status."
    }
}

# Run the function to check AutoRun status
Check-AutoRunStatus

# Function to check Remote Desktop status
function Check-RemoteDesktopStatus {
    Write-OutputToFile "`nChecking Remote Desktop Protocol status..."

    try {
        # Get the current Remote Desktop configuration
        $RDPStatus = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections").fDenyTSConnections

        if ($RDPStatus -eq 0) {
            Write-OutputToFile "Remote Desktop Protocol is ENABLED."
        } else {
            Write-OutputToFile "Remote Desktop Protocol is DISABLED."
        }
    } catch {
        Write-OutputToFile "An error occurred while checking Remote Desktop Protocol status."
    }
}

# Run the function to check Remote Desktop status
Check-RemoteDesktopStatus

# Function to check Antivirus Software status
function Check-AntivirusStatus {
    Write-OutputToFile "`nChecking Antivirus Software status..."

    try {
        # Get the status of antivirus products on the system from the Security Center
        $antivirusProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct"

        if ($antivirusProducts) {
            foreach ($product in $antivirusProducts) {
                $productName = $product.displayName
                $productStatus = "Unknown"
                
                # The productState property is a bit field; the following are common values
                # 266240 (0x41000) = "Up to date"
                # 266256 (0x41010) = "Out of date"
                # 397568 = that the antivirus is installed, real-time protection is enabled, and the virus definitions are up to date.
                switch ($product.productState) {
                    266240 { $productStatus = "Up to date" }
                    266256 { $productStatus = "Out of date" }
                    397568 { $productStatus = "Up to date with real-time protection" } 
                    default { $productStatus = "Unknown status code: $($product.productState)" }
                }
                
                Write-OutputToFile "Antivirus Product: $productName - Status: $productStatus"
            }
        } else {
            Write-OutputToFile "WARNING: No Antivirus product found. :WARNING"
        }
    } catch {
        Write-OutputToFile "An error occurred while checking Antivirus Software status."
    }
}

# Run the function to check Antivirus Software status
Check-AntivirusStatus

# Function to check Security Services status
function Check-SecurityServicesStatus {
    Write-OutputToFile "`nChecking Security Services status..."

    # Define the critical security services to check
    $securityServices = @("wscsvc", "CryptSvc", "Dnscache", "WdNisSvc", "MpsSvc")

    foreach ($service in $securityServices) {
        try {
            $serviceStatus = Get-Service -Name $service -ErrorAction Stop

            if ($serviceStatus.Status -eq "Running") {
                Write-OutputToFile "$($serviceStatus.DisplayName) is RUNNING."
            } else {
                Write-OutputToFile "WARNING: $($serviceStatus.DisplayName) is NOT RUNNING. :WARNING"
            }
        } catch {
            Write-OutputToFile "WARNING: Unable to retrieve status for service $service. It might be disabled or not applicable to this system. :WARNING"
        }
    }
}

Write-OutputToFile "`nSystem Restore Point"

try {
    $restorePoints = Get-ComputerRestorePoint
    
    if ($restorePoints) {
        Write-OutputToFile "Found $($restorePoints.Count) System Restore Point(s):"
        foreach ($restorePoint in $restorePoints) {
            Write-OutputToFile "Description: $($restorePoint.Description); Creation Time: $($restorePoint.CreationTime)"
        }
    } else {
        Write-OutputToFile "No system restore points were found."
    }
} catch {
    Write-OutputToFile "Error occurred while retrieving system restore points: $_"
}


# Run the function to check Security Services status
Check-SecurityServicesStatus

# Function to list open ports
function List-OpenPorts {
    Write-OutputToFile "`nListing open ports..."

    # Capture the result of netstat -ano, which lists ports and associated PIDs
    try {
        $netstat = netstat -ano | Select-String -Pattern "\s+LISTENING" | ForEach-Object { $_ -replace "\s+", "," } | ConvertFrom-Csv -Header Protocol, LocalAddress, ForeignAddress, State, PID
    } catch {
        Write-OutputToFile "WARNING: Failed to retrieve open ports information. :WARNING"
        return
    }

    $listeningPorts = @()

    foreach ($entry in $netstat) {
        if ($entry.PID -match '\d+') { # Ensure that PID is a number
            $port = $entry.LocalAddress.Split(":")[-1]
            $process = Get-Process -Id $entry.PID -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

            if ($process) {
                $listeningPorts += "$($entry.Protocol) port $port is open on process $($process) (PID: $($entry.PID))."
            } else {
                $listeningPorts += "$($entry.Protocol) port $port is open on an unknown process (PID: $($entry.PID))."
            }
        }
    }

    if ($listeningPorts.Length -eq 0) {
        Write-OutputToFile "No open ports found."
    } else {
        Write-OutputToFile "Open ports:"
        foreach ($port in $listeningPorts) {
            Write-OutputToFile $port
        }
    }
}


# Get all the listening ports function
function Get-ListeningPorts {
    Write-OutputToFile "`nChecking for open ports..."

    # Run netstat -ano to get a list of all ports and their statuses
    $netstat = netstat -ano | Select-String "LISTENING"

    # Check if there are any ports in LISTENING state
    if ($netstat) {
        Write-OutputToFile "The following ports are open (in LISTENING state):"

        # Parse the results of netstat
        $listeningPorts = $netstat | ForEach-Object {
            $parts = $_ -split '\s+', 0, "RegexMatch" # split each line by spaces using regex match
            [PSCustomObject]@{ # create a new object for each line
                Protocol = $parts[1]
                LocalAddress = $parts[2] -split ':', 0, "RegexMatch" | Select-Object -Last 1
                PID = $parts[5]
            }
        }

        # Output the results
        $listeningPorts | ForEach-Object {
            Write-OutputToFile ("Protocol: " + $_.Protocol + " Port: " + $_.LocalAddress + " PID: " + $_.PID)
        }
    } else {
        Write-OutputToFile "No open ports in LISTENING state found."
    }
}

# Execute the function
Get-ListeningPorts

# Define the timeframe to query - the last 72 hours in this case
$TimeSpan = New-TimeSpan -Hours 72
$StartTime = (Get-Date).Add(-$TimeSpan)

# Specify the logs to check
$Logs = @('System', 'Application')

foreach ($Log in $Logs) {
    Write-OutputToFile "`nChecking the $Log log for errors and warnings..."

    # Fetch Error events
    $ErrorEvents = Get-WinEvent -FilterHashtable @{LogName=$Log; Level=2; StartTime=$StartTime} -ErrorAction SilentlyContinue

    if ($ErrorEvents) {
        $GroupedErrors = $ErrorEvents | Group-Object {$_.Id, $_.Message -join ' - '} # Group by ID and Message
        Write-OutputToFile "Found $($GroupedErrors.Count) unique error events in the last $($TimeSpan)."


        foreach ($Group in $GroupedErrors) {
            $EventDetails = $Group.Group | Select-Object -First 1 # Select one event from the group for details
            Write-OutputToFile "Error Event: $($EventDetails.Id) occurred $($Group.Count) times - $($EventDetails.Message)"
        }
    } else {
        Write-OutputToFile "No error events in the last $($TimeSpan)."
    }

    # Fetch Warning events
    $WarningEvents = Get-WinEvent -FilterHashtable @{LogName=$Log; Level=3; StartTime=$StartTime} -ErrorAction SilentlyContinue

    if ($WarningEvents) {
        $GroupedWarnings = $WarningEvents | Group-Object {$_.Id, $_.Message -join ' - '} # Group by ID and Message
        Write-OutputToFile "Found $($GroupedWarnings.Count) unique warning events in the $($TimeSpan)."

        foreach ($Group in $GroupedWarnings) {
            $EventDetails = $Group.Group | Select-Object -First 1 # Select one event from the group for details
            Write-OutputToFile "Warning Event: $($EventDetails.Id) occurred $($Group.Count) times - $($EventDetails.Message)"
        }
    } else {
        Write-OutputToFile "No warning events in the last $($TimeSpan)."
    }
}

# Define the Event ID of interest - 4625 for failed login attempts
$EventID = 4625

# Fetch the events
$FailedLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=$EventID; StartTime=$StartTime} -ErrorAction SilentlyContinue

if ($FailedLogins) {
    $FailedLoginCount = $FailedLogins.Count
    Write-OutputToFile "`nThere were $FailedLoginCount failed login attempts in the last 24 hours."
    # To make it more user-friendly, you can list each event with its time, like so:
    foreach ($event in $FailedLogins) {
        $eventTime = $event.TimeCreated
        Write-OutputToFile "Failed login attempt at: $eventTime"
    }
} else {
    Write-OutputToFile "`nNo failed login attempts in the last 24 hours."
}

Write-OutputToFile "`nScheduled Tasks Analysis"

try {
    $scheduledTasks = Get-ScheduledTask | Where-Object {$_.Principal.RunLevel -eq 'HighestAvailable'}

    if ($scheduledTasks) {
        Write-OutputToFile "Found $($scheduledTasks.Count) Scheduled Task(s) set to run with high privileges:"
        foreach ($task in $scheduledTasks) {
            Write-OutputToFile "Task Name: $($task.TaskName); Task Path: $($task.TaskPath); Next Run Time: $($task.NextRunTime)"
        }
    } else {
        Write-OutputToFile "No scheduled tasks are set to run with high-level privileges."
    }
} catch {
    Write-OutputToFile "Error occurred while retrieving scheduled tasks: $_"
}

Write-OutputToFile "`nSecure Boot Status"

try {
    $secureBootStatus = Confirm-SecureBootUEFI

    if ($secureBootStatus) {
        Write-OutputToFile "Secure Boot is enabled."
    } else {
        Write-OutputToFile "Secure Boot is not enabled or not supported by the system."
    }
} catch {
    Write-OutputToFile "Error occurred while checking Secure Boot status: $_"
}

Write-OutputToFile "`nActive Network Connections"

try {
    $activeConnections = Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'}

    if ($activeConnections) {
        Write-OutputToFile "Found $($activeConnections.Count) active network connection(s):"
        foreach ($connection in $activeConnections) {
            Write-OutputToFile "Local Address: $($connection.LocalAddress); Remote Address: $($connection.RemoteAddress); Port: $($connection.RemotePort)"
        }
    } else {
        Write-OutputToFile "No active network connections are present."
    }
} catch {
    Write-OutputToFile "Error occurred while retrieving active network connections: $_"
}


# 21.	Startup Applications: List all startup applications.
# Get-StartUpApplications.ps1
# This script retrieves a list of applications that start up automatically when the system boots.

Write-OutputToFile "`nRetrieving list of startup applications..."

# Fetch startup items for the current user
$CurrentUserStartUpItems = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Select-Object -Property * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider

# Fetch startup items for all users
$AllUsersStartUpItems = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | Select-Object -Property * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider

# Combine the results
$StartUpItems = $CurrentUserStartUpItems, $AllUsersStartUpItems

# Output the results
$StartUpItems | ForEach-Object {
    $properties = $_.PSObject.Properties
    foreach ($property in $properties) {
        Write-OutputToFile "$($property.Name): $($property.Value)"
    }
}

Write-OutputToFile "Startup applications retrieval completed."

# retrieves a list of all scheduled tasks on the system that have run at least once.

Write-OutputToFile "`nRetrieving list of scheduled tasks..."

# Get all scheduled tasks
$ScheduledTasks = Get-ScheduledTask | Where-Object {$_.State -ne "Disabled" -and $_.LastRunTime -ne $null -and $_.NextRunTime -ne $null}

foreach ($task in $ScheduledTasks) {
    Write-OutputToFile "Task Name: $($task.TaskName)"
    Write-OutputToFile "Task Path: $($task.TaskPath)"
    Write-OutputToFile "Next Run Time: $($task.NextRunTime)"
    Write-OutputToFile "Last Run Time: $($task.LastRunTime)"
    Write-OutputToFile "Last Run Result: $($task.LastTaskResult)"
    Write-OutputToFile "Status: $($task.State)"
    Write-OutputToFile "------------------------"
}

if ($ScheduledTasks.Count -eq 0) {
    Write-OutputToFile "No scheduled tasks with run history found."
} else {
    Write-OutputToFile "Scheduled tasks retrieval completed."
}


# Function to write output to the text file
function Write-OutputToFile ($Message) {
    Write-Output $Message | Out-File -FilePath $outputFile -Append -Encoding UTF8
}

# End of the report
Write-OutputToFile "`n----- End of Report -----"

# COMMENT OUT IF RUNNING MULTIPLE REPORTS AT ONCE
# Open the report after the script has finished
Invoke-Item $outputFile
