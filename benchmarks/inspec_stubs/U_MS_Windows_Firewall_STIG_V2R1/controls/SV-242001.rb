control 'SV-242001' do
  title 'The Windows Firewall with Advanced Security must log successful connections when connected to a private network.'
  desc 'A firewall provides a line of defense against attack.  To be effective, it must be enabled and properly configured.  Logging of successful connections for a private network connection will be enabled  to maintain an audit trail if issues are discovered.'
  desc 'check', "If the firewall's Private Profile is not enabled (see V-17416), this requirement is also a finding.

If the following policy-based registry value exists and is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging\\

Value Name:  LogSuccessfulConnections

Type:  REG_DWORD
Value:  0x00000001 (1)

If the policy-based registry value does not exist, verify the following registry value. If it is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\Logging\\

Value Name:  LogSuccessfulConnections

Type:  REG_DWORD
Value:  0x00000001 (1)"
  desc 'fix', 'The preferred method of configuring the firewall settings is with a policy, particularly in a domain environment.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Windows Firewall with Advanced Security -> Windows Firewall with Advanced Security -> Windows Firewall Properties (this link will be in the right pane) -> Private Profile Tab -> Logging (select Customize), "Logged successful connections" to "Yes".

In addition to using policies, systems may also be configured using the firewall GUI or Netsh commands.  These methods may be more appropriate for standalone systems.
The configuration settings in the GUI are the same as those specified in the policy above.  Windows Firewall Properties will be a link in the center pane after opening Windows Firewall with Advanced Security.

The following Netsh commands may also be used to configure this setting:
"Netsh advfirewall set privateprofile logging allowedconnections enable".
Or
"Netsh advfirewall set allprofiles logging allowedconnections enable".'
  impact 0.3
  ref 'DPMS Target Windows Firewall with Advanced Security'
  tag check_id: 'C-45276r698242_chk'
  tag severity: 'low'
  tag gid: 'V-242001'
  tag rid: 'SV-242001r698244_rule'
  tag stig_id: 'WNFWA-000019'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-45235r698243_fix'
  tag 'documentable'
  tag legacy: ['V-17437', 'SV-54905']
  tag cci: ['CCI-001462']
  tag nist: ['AU-14 (2)']
end
