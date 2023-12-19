control 'SV-242006' do
  title 'The Windows Firewall with Advanced Security log size must be configured for public network connections.'
  desc 'A firewall provides a line of defense against attack.  To be effective, it must be enabled and properly configured.  The firewall log file size for a public network connection will be set  to ensure enough capacity is allocated for audit data.'
  desc 'check', "If the firewall's Public Profile is not enabled (see V-17417), this requirement is also a finding.

If the following policy-based registry value exists and is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging\\

Value Name:  LogFileSize

Type:  REG_DWORD
Value:  0x00004000 (16384) (or greater)

If the policy-based registry value does not exist, verify the following registry value. If it is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile\\Logging\\

Value Name:  LogFileSize

Type:  REG_DWORD
Value:  0x00004000 (16384) (or greater)"
  desc 'fix', 'The preferred method of configuring the firewall settings is with a policy, particularly in a domain environment.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Windows Firewall with Advanced Security -> Windows Firewall with Advanced Security -> Windows Firewall Properties (this link will be in the right pane) -> Public Profile Tab -> Logging (select Customize), "Size limit (KB)" to "16,384" or greater.

In addition to using policies, systems may also be configured using the firewall GUI or Netsh commands.  These methods may be more appropriate for standalone systems.
The configuration settings in the GUI are the same as those specified in the policy above.  Windows Firewall Properties will be a link in the center pane after opening Windows Firewall with Advanced Security.

The following Netsh command may also be used to configure this setting:
"Netsh advfirewall set publicprofile logging maxfilesize 16384" or greater.'
  impact 0.3
  ref 'DPMS Target Windows Firewall with Advanced Security'
  tag check_id: 'C-45281r698257_chk'
  tag severity: 'low'
  tag gid: 'V-242006'
  tag rid: 'SV-242006r698259_rule'
  tag stig_id: 'WNFWA-000027'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-45240r698258_fix'
  tag 'documentable'
  tag legacy: ['V-17445', 'SV-54921']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
