control 'SV-48433' do
  title 'IPv6 TCP data retransmissions must be configured to prevent resources from becoming exhausted.'
  desc 'Configuring Windows to limit the number of times that IPv6 TCP retransmits unacknowledged data segments before aborting the attempt helps prevent resources from becoming exhausted.'
  desc 'check', %q(Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.)

If the value for "MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)" is not set to "3" or less, this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\

Value Name:  TcpMaxDataRetransmissions

Type:  REG_DWORD
Value:  3 (or less))
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)" to "3" or less.'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45100r3_chk'
  tag severity: 'low'
  tag gid: 'V-21956'
  tag rid: 'SV-48433r3_rule'
  tag stig_id: 'WN08-SO-000047'
  tag gtitle: 'IPv6 TCP Data Retransmissions'
  tag fix_id: 'F-41562r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
