control 'SV-54904' do
  title 'The Windows Firewall with Advanced Security must log dropped packets when connected to a private network.'
  desc 'A firewall provides a line of defense against attack.  To be effective, it must be enabled and properly configured.   Logging of dropped packets for a private network connection will be enabled  to maintain an audit trail of potential issues.'
  desc 'check', "If the firewall's Private Profile is not enabled (see V-17416), this requirement is also a finding.

If the following policy-based registry value exists and is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging\\

Value Name:  LogDroppedPackets

Type:  REG_DWORD
Value:  0x00000001 (1)

If the policy-based registry value does not exist, verify the following registry value. If it is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\Logging\\

Value Name:  LogDroppedPackets

Type:  REG_DWORD
Value:  0x00000001 (1)"
  desc 'fix', 'The preferred method of configuring the firewall settings is with a policy, particularly in a domain environment.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Windows Firewall with Advanced Security -> Windows Firewall with Advanced Security -> Windows Firewall Properties (this link will be in the right pane) -> Private Profile Tab -> Logging (select Customize), "Log dropped packets" to "Yes".

In addition to using policies, systems may also be configured using the firewall GUI or Netsh commands.  These methods may be more appropriate for standalone systems.
The configuration settings in the GUI are the same as those specified in the policy above.  Windows Firewall Properties will be a link in the center pane after opening Windows Firewall with Advanced Security.

The following Netsh commands may also be used to configure this setting:
"Netsh advfirewall set privateprofile logging droppedconnections enable".
Or
"Netsh advfirewall set allprofiles logging droppedconnections enable".'
  impact 0.3
  ref 'DPMS Target Windows Firewall with Advanced Security'
  tag check_id: 'C-61113r1_chk'
  tag severity: 'low'
  tag gid: 'V-17436'
  tag rid: 'SV-54904r3_rule'
  tag stig_id: 'WNFWA-000018'
  tag gtitle: 'Windows Firewall Private - Log Dropped Packets'
  tag fix_id: 'F-63511r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
