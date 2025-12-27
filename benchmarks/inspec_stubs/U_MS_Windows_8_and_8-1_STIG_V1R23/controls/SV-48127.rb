control 'SV-48127' do
  title 'The system must limit how many times unacknowledged TCP data is retransmitted.'
  desc 'In a SYN flood attack, the attacker sends a continuous stream of SYN packets to a server, and the server leaves the half-open connections open until it is overwhelmed and is no longer able to respond to legitimate requests.'
  desc 'check', %q(Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.)

If the value for "MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)" is not set to "3" or less, this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\

Value Name:  TcpMaxDataRetransmissions

Value Type:  REG_DWORD
Value:  3 (or less))
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)" to "3" or less.'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44853r2_chk'
  tag severity: 'low'
  tag gid: 'V-4438'
  tag rid: 'SV-48127r2_rule'
  tag stig_id: 'WN08-SO-000048'
  tag gtitle: 'TCP Data Retransmissions'
  tag fix_id: 'F-41264r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
