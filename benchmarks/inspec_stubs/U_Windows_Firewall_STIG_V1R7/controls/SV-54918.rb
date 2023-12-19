control 'SV-54918' do
  title 'The Windows Firewall with Advanced Security local connection rules must not be merged with Group Policy settings when connected to a public network.'
  desc 'A firewall provides a line of defense against attack.  To be effective, it must be enabled and properly configured.  Local connection rules will not be merged with Group Policy settings on a public network to prevent Group Policy settings from being changed.'
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

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Windows Firewall with Advanced Security -> Windows Firewall with Advanced Security -> Windows Firewall Properties (this link will be in the right pane) -> Public Profile Tab -> Settings (select Customize) -> Rule merging, "Apply local connection security rules:" to "No".'
  impact 0.5
  ref 'DPMS Target Windows Firewall with Advanced Security'
  tag check_id: 'C-61133r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17443'
  tag rid: 'SV-54918r3_rule'
  tag stig_id: 'WNFWA-000025'
  tag gtitle: 'Windows Firewall Public - Local Connection Rules'
  tag fix_id: 'F-63525r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
