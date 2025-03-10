control 'SV-25279' do
  title 'IPv6 TCP data retransmissions must be configured to prevent resources from becoming exhausted.'
  desc 'Configuring Windows to limit the number of times that IPv6 TCP retransmits unacknowledged data segments before aborting the attempt helps prevent resources from becoming exhausted.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)" is not set to "3" or less, this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\

Value Name:  TcpMaxDataRetransmissions

Type:  REG_DWORD
Value:  3 (or less)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)" to "3" or less.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-60819r3_chk'
  tag severity: 'low'
  tag gid: 'V-21956'
  tag rid: 'SV-25279r2_rule'
  tag gtitle: 'IPv6 TCP Data Retransmissions'
  tag fix_id: 'F-65551r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
