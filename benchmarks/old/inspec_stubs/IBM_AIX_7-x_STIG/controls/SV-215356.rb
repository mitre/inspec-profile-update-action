control 'SV-215356' do
  title 'If DHCP is not enabled in the network on AIX, the dhcprd daemon must be disabled.'
  desc 'The dhcprd daemon listens for broadcast packets, receives them, and forwards them to the appropriate server.

To prevent remote attacks this daemon should not be enabled unless there is no alternative.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^start[[:blank:]]/usr/sbin/dhcprd" /etc/rc.tcpip

If there is any output from the command, this is a finding.'
  desc 'fix', 'In "/etc/rc.tcpip", comment out the "dhcprd" entry by running command: 
# chrctcp -d dhcprd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16554r294519_chk'
  tag severity: 'medium'
  tag gid: 'V-215356'
  tag rid: 'SV-215356r508663_rule'
  tag stig_id: 'AIX7-00-003050'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16552r294520_fix'
  tag 'documentable'
  tag legacy: ['V-91337', 'SV-101435']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
