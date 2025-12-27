control 'SV-243451' do
  title 'Device Guard Code Integrity Policy must be used on the Windows PAW to restrict applications that can run on the system (Device Guard User Mode Code Integrity).'
  desc 'A main security architectural construct of a PAW is to restrict non-administrative applications and functions from the PAW workstation. Many standard user applications and functions, including email processing, Internet browsing, and using business applications, can increase the security risk to the workstation. These apps and functions are susceptible to many security vulnerabilities, including phishing attacks and embedded malware. This increased risk is not acceptable for the highly privileged activities of a PAW.'
  desc 'check', 'Note: This requirement is Not Applicable (NA) if the Endpoint Security Solution (ESS) managed system is used on the PAW and application white listing is enforced.

Verify Device Guard is enforcing a code integrity policy to restrict authorized applications.

Run "PowerShell" with elevated privileges (run as administrator).

Enter the following:

"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | FL *codeintegrity*"

If "UserModeCodeIntegrityPolicyEnforcementStatus" does not have a value of "2" indicating "Enforced", this is a finding.

(For reference: 0 - Not Configured; 1 - Audit; 2 - Enforced)

Alternately:

- Run "System Information".
- Under "System Summary", verify the following:

If "Device Guard user mode Code Integrity" does not display "Enforced", this is finding.'
  desc 'fix', 'Implement a whitelist of authorized PAW applications using Device Guard. See the Device Guard Deployment Guide (https://docs.microsoft.com/en-us/windows/device-security/device-guard/device-guard-deployment-guide) for deployment information and hardware requirements and the IAD Device Guard document "Implementing a Secure Administrative Workstation using Device Guard" at https://github.com/iadgov/Secure-Host-Baseline/tree/master/Device%20Guard.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows PAW'
  tag check_id: 'C-46726r804961_chk'
  tag severity: 'medium'
  tag gid: 'V-243451'
  tag rid: 'SV-243451r804962_rule'
  tag stig_id: 'WPAW-00-001060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-46683r722923_fix'
  tag 'documentable'
  tag legacy: ['V-78163', 'SV-92869']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
