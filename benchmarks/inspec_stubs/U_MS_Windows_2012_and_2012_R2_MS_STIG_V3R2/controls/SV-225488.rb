control 'SV-225488' do
  title 'IPv6 TCP data retransmissions must be configured to prevent resources from becoming exhausted.'
  desc 'Configuring Windows to limit the number of times that IPv6 TCP retransmits unacknowledged data segments before aborting the attempt helps prevent resources from becoming exhausted.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\

Value Name:  TcpMaxDataRetransmissions

Value Type:  REG_DWORD
Value:  3 (or less)'
  desc 'fix', %q(Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)" to "3" or less.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.))
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27187r471806_chk'
  tag severity: 'low'
  tag gid: 'V-225488'
  tag rid: 'SV-225488r569185_rule'
  tag stig_id: 'WN12-SO-000047'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-27175r471807_fix'
  tag 'documentable'
  tag legacy: ['SV-53181', 'V-21956']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
