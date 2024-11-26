control 'SV-88167' do
  title 'Windows Server 2016 must be running Credential Guard on domain-joined member servers.'
  desc 'Credential Guard uses virtualization-based security to protect data that could be used in credential theft attacks if compromised. This authentication information, which was stored in the Local Security Authority (LSA) in previous versions of Windows, is isolated from the rest of operating system and can only be accessed by privileged system software.'
  desc 'check', 'For domain controllers and standalone systems, this is NA.

Current hardware and virtual environments may not support virtualization-based security features, including Credential Guard, due to specific supporting requirements, including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V feature within a virtual machine.

Open "PowerShell" with elevated privileges (run as administrator).

Enter the following:

"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard"

If "SecurityServicesRunning" does not include a value of "1" (e.g., "{1, 2}"), this is a finding.

Alternately:

Run "System Information".

Under "System Summary", verify the following:

If "Device Guard Security Services Running" does not list "Credential Guard", this is finding.

The policy settings referenced in the Fix section will configure the following registry value. However, due to hardware requirements, the registry value alone does not ensure proper function.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard\\

Value Name: LsaCfgFlags
Value Type: REG_DWORD
Value: 0x00000001 (1) (Enabled with UEFI lock)

A Microsoft article on Credential Guard system requirement can be found at the following link:

https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Device Guard >> "Turn On Virtualization Based Security" to "Enabled" with "Enabled with UEFI lock" selected for "Credential Guard Configuration".

A Microsoft article on Credential Guard system requirement can be found at the following link:

https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements'
  impact 0.7
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-90067r2_chk'
  tag severity: 'high'
  tag gid: 'V-73515'
  tag rid: 'SV-88167r4_rule'
  tag stig_id: 'WN16-MS-000120'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-97111r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
