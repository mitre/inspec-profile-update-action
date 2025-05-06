control 'SV-25077' do
  title 'The system must limit how many times unacknowledged TCP data is retransmitted.'
  desc 'In a SYN flood attack, the attacker sends a continuous stream of SYN packets to a server, and the server leaves the half-open connections open until it is overwhelmed and no longer is able to respond to legitimate requests.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)" is not set to "3" or less, this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

Value Name:  TcpMaxDataRetransmissions

Value Type:  REG_DWORD
Value:  3 (or less)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)" to "3" or less.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62013r1_chk'
  tag severity: 'low'
  tag gid: 'V-4438'
  tag rid: 'SV-25077r2_rule'
  tag gtitle: 'TCP Data Retransmissions'
  tag fix_id: 'F-66909r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
