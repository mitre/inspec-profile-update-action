control 'SV-215359' do
  title 'If AIX server is not functioning as a multicast router, the mrouted daemon must be disabled.'
  desc 'This daemon is an implementation of the multicast routing protocol.

To prevent remote attacks this daemon should not be enabled unless there is no alternative.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^start[[:blank:]]/usr/sbin/mrouted" /etc/rc.tcpip

If there is any output from the command, this is a finding.'
  desc 'fix', 'In "/etc/rc.tcpip", comment out the "mrouted" entry by running command: 
# chrctcp -d mrouted'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16557r294528_chk'
  tag severity: 'medium'
  tag gid: 'V-215359'
  tag rid: 'SV-215359r508663_rule'
  tag stig_id: 'AIX7-00-003053'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16555r294529_fix'
  tag 'documentable'
  tag legacy: ['SV-101443', 'V-91345']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
