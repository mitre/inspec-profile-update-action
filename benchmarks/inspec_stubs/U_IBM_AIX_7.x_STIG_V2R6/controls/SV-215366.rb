control 'SV-215366' do
  title 'The aixmibd daemon must be disabled on AIX.'
  desc 'The aixmibd daemon is a dpi2 sub-agent which manages a number of MIB variables. 

To prevent attacks this daemon should not be enabled unless there is no alternative.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^start[[:blank:]]/usr/sbin/aixmibd" /etc/rc.tcpip

If there is any output from the command, this is a finding.'
  desc 'fix', 'In "/etc/rc.tcpip", comment out the "aixmibd" entry by running command: 
# chrctcp -d aixmibd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16564r294549_chk'
  tag severity: 'medium'
  tag gid: 'V-215366'
  tag rid: 'SV-215366r508663_rule'
  tag stig_id: 'AIX7-00-003061'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16562r294550_fix'
  tag 'documentable'
  tag legacy: ['V-91361', 'SV-101459']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
