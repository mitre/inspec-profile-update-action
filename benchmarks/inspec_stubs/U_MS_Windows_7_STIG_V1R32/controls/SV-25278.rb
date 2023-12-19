control 'SV-25278' do
  title 'IPv6 source routing must be configured to highest protection.'
  desc 'Configuring the system to disable IPv6 source routing protects against spoofing.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)" is not set to "Highest protection, source routing is completely disabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\

Value Name:  DisableIpSourceRouting

Type:  REG_DWORD
Value:  2'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)" to "Highest protection, source routing is completely disabled".'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-60817r2_chk'
  tag severity: 'low'
  tag gid: 'V-21955'
  tag rid: 'SV-25278r2_rule'
  tag gtitle: 'IPv6 Source Routing'
  tag fix_id: 'F-65549r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
