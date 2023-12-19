control 'SV-215362' do
  title 'If rwhod is not required on AIX, the rwhod daemon must be disabled.'
  desc 'This is the remote WHO service.

To prevent remote attacks this daemon should not be enabled unless there is no alternative.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^start[[:blank:]]/usr/sbin/rwhod" /etc/rc.tcpip

If there is any output from the command, this is a finding.'
  desc 'fix', 'In "/etc/rc.tcpip", comment out the "rwhod" entry by running command: 
# chrctcp -d rwhod'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16560r294537_chk'
  tag severity: 'medium'
  tag gid: 'V-215362'
  tag rid: 'SV-215362r508663_rule'
  tag stig_id: 'AIX7-00-003056'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16558r294538_fix'
  tag 'documentable'
  tag legacy: ['SV-101449', 'V-91351']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
