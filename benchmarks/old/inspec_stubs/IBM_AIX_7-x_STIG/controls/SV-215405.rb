control 'SV-215405' do
  title 'If DHCP server is not required on AIX, the DHCP server must be disabled.'
  desc 'The dhcpsd daemon is the DHCP server that serves addresses and configuration information to DHCP clients in the network.

To prevent remote attacks this daemon should not be enabled unless there is no alternative.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^start[[:blank:]]/usr/sbin/dhcpsd" /etc/rc.tcpip

If there is any output from the command, this is a finding.'
  desc 'fix', 'In "/etc/rc.tcpip", comment out the "dhcpsd" entry by running command: 
# chrctcp -d dhcpsd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16603r294666_chk'
  tag severity: 'medium'
  tag gid: 'V-215405'
  tag rid: 'SV-215405r508663_rule'
  tag stig_id: 'AIX7-00-003104'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16601r294667_fix'
  tag 'documentable'
  tag legacy: ['SV-101437', 'V-91339']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
