# Win11-SecCheck-PowerShell
Windows 11 Security Checks for PowerShell. Designed for both local and mass network use.

There is commented out code to have output to a network path instead. This is meant for running on a domain and capturing alot of Windows devices, I expect it may work just fine on Win 10 and earlier but is untested. 

Done:
1.	Windows Firewall Status: Checks if the firewall is active, as it's crucial for blocking unauthorized access.
2.	User Account Control (UAC) Status: Ensures that UAC is enabled to prevent unauthorized changes.
3.	Windows Defender Status: Verifies if Windows Defender is active and up-to-date, as it's the first line of defense against malware.
4.	BitLocker Status: Checks if BitLocker is enabled to ensure data encryption and protection.
5.	Operating System Updates: Confirms that the OS is up-to-date, as updates often include critical security patches.
6.	Password Policy: Evaluates the system's password policy for robustness (e.g., minimum length, complexity requirements).
7.	Failed Login Attempts: Reviews the security event log for multiple failed login attempts, which could indicate unauthorized access attempts.
8.	Admin Users: Lists all users with administrative privileges, as having too many admin users can pose a security risk.
9.	Guest Account Status: Ensures the guest account is disabled when not in use to prevent unauthorized access.
10.	Network Shares: Lists all network shares and their permissions to review potential security vulnerabilities.
11.	AutoRun Status: Checks if AutoRun is disabled to prevent malware from spreading through removable media.


Current Todo:
12.	Remote Desktop Status: Verifies if Remote Desktop is enabled and if so, ensures it’s configured securely (e.g., requiring Network Level Authentication).
13.	Antivirus Software Status: In addition to Windows Defender, checks for the presence and status of any third-party antivirus software.
14.	System Restore Point: Checks for the latest system restore point, ensuring that it's recent in case a quick system recovery is needed.
15.	Security Services Status: Confirms that critical security services like Windows Security Center, Cryptographic Services, etc., are running.
16.	Open Ports: Lists open network ports and associated services to identify potential vulnerabilities.
17.	Windows Event Logs: Reviews critical system and security logs for any significant incidents or warnings.

