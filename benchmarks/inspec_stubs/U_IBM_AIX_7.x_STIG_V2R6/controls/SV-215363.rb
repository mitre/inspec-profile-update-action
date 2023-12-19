control 'SV-215363' do
  title 'The timed daemon must be disabled on AIX.'
  desc 'This is the old UNIX time service.

The timed daemon is the old UNIX time service. Disable this service and use xntp, if time synchronization is required in the environment.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^start[[:blank:]]/usr/sbin/timed" /etc/rc.tcpip

If there is any output from the command, this is a finding.'
  desc 'fix', 'In "/etc/rc.tcpip", comment out the "timed" entry by running command: 
# chrctcp -d timed'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16561r294540_chk'
  tag severity: 'medium'
  tag gid: 'V-215363'
  tag rid: 'SV-215363r508663_rule'
  tag stig_id: 'AIX7-00-003057'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16559r294541_fix'
  tag 'documentable'
  tag legacy: ['SV-101451', 'V-91353']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
