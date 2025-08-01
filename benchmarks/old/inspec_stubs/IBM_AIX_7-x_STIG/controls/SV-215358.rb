control 'SV-215358' do
  title 'If AIX server is not functioning as a network router, the gated daemon must be disabled.'
  desc 'This daemon provides gateway routing functions for protocols such as RIP and SNMP.

To prevent remote attacks this daemon should not be enabled unless there is no alternative.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^start[[:blank:]]/usr/sbin/gated" /etc/rc.tcpip

If there is any output from the command, this is a finding.'
  desc 'fix', 'In "/etc/rc.tcpip", comment out the "gated" entry by running command: 
# chrctcp -d gated'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16556r294525_chk'
  tag severity: 'medium'
  tag gid: 'V-215358'
  tag rid: 'SV-215358r508663_rule'
  tag stig_id: 'AIX7-00-003052'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16554r294526_fix'
  tag 'documentable'
  tag legacy: ['SV-101441', 'V-91343']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
