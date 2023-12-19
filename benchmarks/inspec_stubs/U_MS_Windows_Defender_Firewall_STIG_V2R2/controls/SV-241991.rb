control 'SV-241991' do
  title 'Windows Defender Firewall with Advanced Security must be enabled when connected to a public network.'
  desc 'A firewall provides a line of defense against attack. To be effective, it must be enabled and properly configured. This setting enables the firewall when connected to a public network.'
  desc 'check', 'If the following policy-based registry value exists and is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\

Value Name:  EnableFirewall

Type:  REG_DWORD
Value:  0x00000001 (1)

If the policy-based registry value does not exist, verify the following registry value. If it is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile\\

Value Name:  EnableFirewall

Type:  REG_DWORD
Value:  0x00000001 (1)'
  desc 'fix', 'The preferred method of configuring the firewall settings is with a policy, particularly in a domain environment.

Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Windows Defender Firewall with Advanced Security >> Windows Defender Firewall with Advanced Security >> Windows Defender Firewall Properties (this link will be in the right pane) >> Public Profile tab >> State, "Firewall state" to "On (recommended)".

In addition to using policies, systems may also be configured using the firewall GUI or Netsh commands. These methods may be more appropriate for standalone systems.

The configuration settings in the GUI are the same as those specified in the policy above. Microsoft Defender Firewall Properties will be a link in the center pane after opening Microsoft Defender Firewall with Advanced Security.

The following Netsh commands may also be used to configure this setting:

"Netsh advfirewall set publicprofile state on".
or
"Netsh advfirewall set allprofiles state on".'
  impact 0.5
  ref 'DPMS Target Windows Defender Firewall with Advanced Security'
  tag check_id: 'C-45266r921987_chk'
  tag severity: 'medium'
  tag gid: 'V-241991'
  tag rid: 'SV-241991r922932_rule'
  tag stig_id: 'WNFWA-000003'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-45225r922931_fix'
  tag 'documentable'
  tag legacy: ['V-17417', 'SV-54855']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
