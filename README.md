# Win11-SecCheck-PowerShell
This script performs a comprehensive security analysis of your Windows system by running 20 crucial checks. It's designed to help system administrators and security professionals ensure their Windows environments are secured according to best practices and identify potential vulnerabilities.

Features
The script checks the following system parameters and configurations:
1.	Windows Firewall Status: Verifies if the firewall is active to block unauthorized access.
2.	User Account Control (UAC) Status: Confirms that UAC is enabled to prevent unauthorized changes.
3.	Windows Defender Status: Checks if Windows Defender is active and updated.
4.	BitLocker Status: Verifies if BitLocker is enabled for data protection.
5.	Operating System Updates: Ensures that the OS is current with updates.
6.	Password Policy: Evaluates the robustness of the system's password policy.
7.	Failed Login Attempts: Checks for multiple failed login attempts.
8.	Admin Users: Lists all users with administrative privileges.
9.	Guest Account Status: Confirms the guest account is disabled when not in use.
10.	Network Shares: Reviews all network shares and their permissions.
11.	AutoRun Status: Checks if AutoRun is disabled.
12.	Remote Desktop Status: Verifies the status of Remote Desktop and its configuration.
13.	Antivirus Software Status: Checks for third-party antivirus software and its status.
14.	System Restore Point: Checks for the latest system restore point.
15.	Security Services Status: Confirms critical security services are running.
16.	Open Ports: Lists open network ports and their services.
17.	Windows Event Logs: Reviews system and security logs for significant incidents.
18.	Scheduled Tasks Analysis: Reviews scheduled tasks with high-level privileges.
19.	Secure Boot Status: Verifies if Secure Boot is enabled.
20.	Active Network Connections: Reviews all active network connections.

Requirements
•	Windows PowerShell 5.1 or higher
•	Appropriate administrative privileges to execute system checks


Please reference readme.

