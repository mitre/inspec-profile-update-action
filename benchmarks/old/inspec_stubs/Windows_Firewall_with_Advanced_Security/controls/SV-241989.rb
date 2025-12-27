control 'SV-241989' do
  title 'Windows Defender Firewall with Advanced Security must be enabled when connected to a domain.'
  desc 'A firewall provides a line of defense against attack. To be effective, it must be enabled and properly configured. This setting enables the firewall when connected to the domain.'
  desc 'check', 'If the system is not a member of a domain, the Domain Profile requirements can be marked NA.

If the following policy-based registry value exists and is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\

Value Name:  EnableFirewall

Type:  REG_DWORD
Value:  0x00000001 (1)

If the policy-based registry value does not exist, verify the following registry value. If it is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile\\

Value Name:  EnableFirewall

Type:  REG_DWORD
Value:  0x00000001 (1)'
  desc 'fix', 'The preferred method of configuring the firewall settings is with a policy, particularly in a domain environment.

Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Windows Defender Firewall with Advanced Security >> Windows Defender Firewall with Advanced Security >> Windows Defender Firewall Properties (this link will be in the right pane) >> Domain Profile tab >> State, "Firewall state" to "On (recommended)".

In addition to using policies, systems may also be configured using the firewall GUI or Netsh commands. These methods may be more appropriate for standalone systems.

The configuration settings in the GUI are the same as those specified in the policy above. Microsoft Defender Firewall Properties will be a link in the center pane after opening Microsoft Defender Firewall with Advanced Security.

The following Netsh commands may also be used to configure this setting:

"Netsh advfirewall set domainprofile state on".
or
"Netsh advfirewall set allprofiles state on".'
  impact 0.5
  ref 'DPMS Target Windows Defender Firewall with Advanced Security'
  tag check_id: 'C-45264r921981_chk'
  tag severity: 'medium'
  tag gid: 'V-241989'
  tag rid: 'SV-241989r922928_rule'
  tag stig_id: 'WNFWA-000001'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-45223r922927_fix'
  tag 'documentable'
  tag legacy: ['V-17415', 'SV-54833']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
