control 'SV-242002' do
  title 'The Windows Firewall with Advanced Security must block unsolicited inbound connections when connected to a public network.'
  desc 'A firewall provides a line of defense against attack.  To be effective, it must be enabled and properly configured.  Unsolicited inbound connections may be malicious attempts to gain access to a system.  Unsolicited inbound connections, for which there is no rule allowing the connection, will be blocked on a public network.'
  desc 'check', "If the firewall's Public Profile is not enabled (see V-17417), this requirement is also a finding.

If the following policy-based registry value exists and is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\

Value Name:  DefaultInboundAction

Type:  REG_DWORD
Value:  0x00000001 (1)

If the policy-based registry value does not exist, verify the following registry value. If it is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile\\

Value Name:  DefaultInboundAction

Type:  REG_DWORD
Value:  0x00000001 (1)"
  desc 'fix', 'The preferred method of configuring the firewall settings is with a policy, particularly in a domain environment.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Windows Firewall with Advanced Security -> Windows Firewall with Advanced Security -> Windows Firewall Properties (this link will be in the right pane) -> Public Profile Tab -> State, "Inbound connections" to "Block (default)".

In addition to using policies, systems may also be configured using the firewall GUI or Netsh commands.  These methods may be more appropriate for standalone systems.
The configuration settings in the GUI are the same as those specified in the policy above.  Windows Firewall Properties will be a link in the center pane after opening Windows Firewall with Advanced Security.

The following Netsh commands may also be used to configure this setting:
"Netsh advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound".
Or
"Netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound".
Both inbound and outbound parameters must be specified to execute this command.'
  impact 0.7
  ref 'DPMS Target Windows Firewall with Advanced Security'
  tag check_id: 'C-45277r698245_chk'
  tag severity: 'high'
  tag gid: 'V-242002'
  tag rid: 'SV-242002r698247_rule'
  tag stig_id: 'WNFWA-000020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-45236r698246_fix'
  tag 'documentable'
  tag legacy: ['V-17438', 'SV-54906']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
