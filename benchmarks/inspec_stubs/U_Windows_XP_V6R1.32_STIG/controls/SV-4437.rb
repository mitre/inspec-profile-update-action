control 'SV-4437' do
  title 'TCP connection response retransmissions are not controlled.'
  desc 'In a SYN flood attack, the attacker sends a continuous stream of SYN packets to a server, and the server leaves the half-open connections open until it is overwhelmed and no longer is able to respond to legitimate requests.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “MSS: (TcpMaxConnectResponseRetransmissions) SYN-ACK retransmissions when a connection is not acknowledged” is not set to “3 & 6 seconds, half-open connections dropped after 21 seconds”,  “3 seconds, half-open connections dropped after 9 seconds” or “No retransmission, half-open connections dropped after 3 seconds”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

Value Name:  TcpMaxConnectResponseRetransmissions

Value Type:  REG_DWORD
Value:  2 (3 & 6 seconds), 1 (3 seconds), 0 (No retransmission)
 
 
Warning: Microsoft cautions that setting this to “No retransmission, half-open connections dropped after 3 seconds” may cause legitimate connection attempts from distant clients to fail due to time-out.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (TcpMaxConnectResponseRetransmissions) SYN-ACK retransmissions when a connection is not acknowledged” to “3 & 6 seconds, half-open connections dropped after 21 seconds”,  “3 seconds, half-open connections dropped after 9 seconds” or “No retransmission, half-open connections dropped after 3 seconds”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-2235r1_chk'
  tag severity: 'low'
  tag gid: 'V-4437'
  tag rid: 'SV-4437r1_rule'
  tag gtitle: 'TCP Connection Response Retransmissions'
  tag fix_id: 'F-6084r1_fix'
  tag 'documentable'
  tag potential_impacts: 'Microsoft cautions that setting this to “No retransmission, half-open connections dropped after 3 seconds” may cause legitimate connection attempts from distant clients to fail due to time-out.'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
