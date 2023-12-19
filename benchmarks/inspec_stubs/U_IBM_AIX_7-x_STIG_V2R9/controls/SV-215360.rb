control 'SV-215360' do
  title 'If AIX server is not functioning as a DNS server, the named daemon must be disabled.'
  desc 'This is the server for the DNS protocol and controls domain name resolution for its clients.

To prevent attacks this daemon should not be enabled unless there is no alternative.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^start[[:blank:]]/usr/sbin/named" /etc/rc.tcpip

If there is any output from the command, this is a finding.'
  desc 'fix', 'In "/etc/rc.tcpip", comment out the "named" entry by running command: 
# chrctcp -d named'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16558r294531_chk'
  tag severity: 'medium'
  tag gid: 'V-215360'
  tag rid: 'SV-215360r508663_rule'
  tag stig_id: 'AIX7-00-003054'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16556r294532_fix'
  tag 'documentable'
  tag legacy: ['V-91347', 'SV-101445']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
