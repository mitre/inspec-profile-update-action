control 'SV-215361' do
  title 'If AIX server is not functioning as a network router, the routed daemon must be disabled.'
  desc 'The routed daemon manages the network routing tables in the kernel.

To prevent attacks this daemon should not be enabled unless there is no alternative.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^start[[:blank:]]/usr/sbin/routed" /etc/rc.tcpip

If there is any output from the command, this is a finding.'
  desc 'fix', 'In "/etc/rc.tcpip", comment out the "routed" entry by running command: 
# chrctcp -d routed'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16559r294534_chk'
  tag severity: 'medium'
  tag gid: 'V-215361'
  tag rid: 'SV-215361r508663_rule'
  tag stig_id: 'AIX7-00-003055'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16557r294535_fix'
  tag 'documentable'
  tag legacy: ['V-91349', 'SV-101447']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
