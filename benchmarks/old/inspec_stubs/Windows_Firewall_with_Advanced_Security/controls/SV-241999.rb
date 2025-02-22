control 'SV-241999' do
  title 'Windows Defender Firewall with Advanced Security log size must be configured for private network connections.'
  desc 'A firewall provides a line of defense against attack. To be effective, it must be enabled and properly configured. The firewall log file size for a private connection will be set to ensure enough capacity is allocated for audit data.'
  desc 'check', "If the firewall's Private Profile is not enabled (see V-17416), this requirement is also a finding.

If the following policy-based registry value exists and is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging\\

Value Name:  LogFileSize

Type:  REG_DWORD
Value:  0x00004000 (16384) (or greater)

If the policy-based registry value does not exist, verify the following registry value. If it is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\Logging\\

Value Name:  LogFileSize

Type:  REG_DWORD
Value:  0x00004000 (16384) (or greater)"
  desc 'fix', 'The preferred method of configuring the firewall settings is with a policy, particularly in a domain environment.

Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Windows Defender Firewall with Advanced Security >> Windows Defender Firewall with Advanced Security >> Windows Defender Firewall Properties (this link will be in the right pane) >> Private Profile tab >> Logging (select Customize), "Size limit (KB)" to "16,384" or greater.

In addition to using policies, systems may also be configured using the firewall GUI or Netsh commands. These methods may be more appropriate for standalone systems.

The configuration settings in the GUI are the same as those specified in the policy above. Microsoft Defender Firewall Properties will be a link in the center pane after opening Microsoft Defender Firewall with Advanced Security.

The following Netsh command may also be used to configure this setting:

"Netsh advfirewall set privateprofile logging maxfilesize 16384" or greater.'
  impact 0.3
  ref 'DPMS Target Windows Defender Firewall with Advanced Security'
  tag check_id: 'C-45274r698236_chk'
  tag severity: 'low'
  tag gid: 'V-241999'
  tag rid: 'SV-241999r922948_rule'
  tag stig_id: 'WNFWA-000017'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-45233r922947_fix'
  tag 'documentable'
  tag legacy: ['V-17435', 'SV-54903']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
