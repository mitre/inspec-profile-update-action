control 'SV-254441' do
  title 'Windows Server 2022 must be running Credential Guard on domain-joined member servers.'
  desc 'Credential Guard uses virtualization-based security to protect data that could be used in credential theft attacks if compromised. This authentication information, which was stored in the Local Security Authority (LSA) in previous versions of Windows, is isolated from the rest of operating system and can only be accessed by privileged system software.'
  desc 'check', 'For domain controllers and standalone or nondomain-joined systems, this is NA.

Open "PowerShell" with elevated privileges (run as administrator).

Enter the following:

"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard"

If "SecurityServicesRunning" does not include a value of "1" (e.g., "{1, 2}"), this is a finding.

Alternately:

Run "System Information".

Under "System Summary", verify the following:

If "Device Guard Security Services Running" does not list "Credential Guard", this is a finding.

The policy settings referenced in the Fix section will configure the following registry value. However, due to hardware requirements, the registry value alone does not ensure proper function.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard\\

Value Name: LsaCfgFlags
Value Type: REG_DWORD
Value: 0x00000001 (1) (Enabled with UEFI lock)

A Microsoft article on Credential Guard system requirement can be found at the following link:

https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Device Guard >> Turn On Virtualization Based Security to "Enabled" with "Enabled with UEFI lock" selected for "Credential Guard Configuration".

A Microsoft article on Credential Guard system requirement can be found at the following link:

https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements

Severity Override Guidance: The AO can allow the severity override if they have reviewed the overall protection provided to the affected servers that are not capable of complying with the Credential Guard requirement. Items that must be reviewed/considered for compliance or mitigation for non-Credential Guard compliance are:

The use of Microsoft Local Administrator Password Solution (LAPS) or similar products to control different local administrative passwords for all affected servers. This is to include a strict password change requirement (60 days or less).
....
Strict separation of roles and duties. Server administrator credentials cannot be used on Windows 10 desktop to administer it. Documentation of all exceptions must be supplied.
....
Use of a Privileged Access Workstation (PAW) and adherence to the Clean Source principle for administering affected servers. 
....
Boundary Protection that is currently in place to protect from vulnerabilities in the network/servers.
....
Windows Defender rule block credential stealing from LSASS.exe is applied. This rule can only be applied if Windows Defender is in use.
....
The overall number of vulnerabilities that are unmitigated on the network/servers.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57926r849137_chk'
  tag severity: 'high'
  tag gid: 'V-254441'
  tag rid: 'SV-254441r849139_rule'
  tag stig_id: 'WN22-MS-000140'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57877r849138_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
