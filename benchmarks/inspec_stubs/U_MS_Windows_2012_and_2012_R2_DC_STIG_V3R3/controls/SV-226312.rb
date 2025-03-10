control 'SV-226312' do
  title 'The system must limit how many times unacknowledged TCP data is retransmitted.'
  desc 'In a SYN flood attack, the attacker sends a continuous stream of SYN packets to a server, and the server leaves the half-open connections open until it is overwhelmed and is no longer able to respond to legitimate requests.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

Value Name:  TcpMaxDataRetransmissions

Value Type:  REG_DWORD
Value:  3 (or less)'
  desc 'fix', %q(Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)" to "3" or less.   

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.))
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28014r476780_chk'
  tag severity: 'low'
  tag gid: 'V-226312'
  tag rid: 'SV-226312r794565_rule'
  tag stig_id: 'WN12-SO-000048'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-28002r476781_fix'
  tag 'documentable'
  tag legacy: ['SV-52929', 'V-4438']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
