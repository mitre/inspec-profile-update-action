control 'SV-242005' do
  title 'Windows Defender Firewall with Advanced Security local connection rules must not be merged with Group Policy settings when connected to a public network.'
  desc 'A firewall provides a line of defense against attack. To be effective, it must be enabled and properly configured. Local connection rules will not be merged with Group Policy settings on a public network to prevent Group Policy settings from being changed.'
  desc 'check', "If the system is not a member of a domain, this is NA.

If the firewall's Public Profile is not enabled (see V-17417), this requirement is also a finding.

Verify the registry value below.

If this registry value does not exist or is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\

Value Name:  AllowLocalIPsecPolicyMerge

Type:  REG_DWORD
Value:  0x00000000 (0)"
  desc 'fix', 'If the system is not a member of a domain, this is NA.

Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Windows Defender Firewall with Advanced Security >> Windows Defender Firewall with Advanced Security >> Windows Defender Firewall Properties (this link will be in the right pane) >> Public Profile tab >> Settings (select Customize) >> Rule merging, "Apply local connection security rules:" to "No".'
  impact 0.5
  ref 'DPMS Target Windows Defender Firewall with Advanced Security'
  tag check_id: 'C-45280r698254_chk'
  tag severity: 'medium'
  tag gid: 'V-242005'
  tag rid: 'SV-242005r922960_rule'
  tag stig_id: 'WNFWA-000025'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-45239r922959_fix'
  tag 'documentable'
  tag legacy: ['V-17443', 'SV-54918']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
