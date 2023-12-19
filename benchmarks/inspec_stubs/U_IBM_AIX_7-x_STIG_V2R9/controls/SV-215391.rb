control 'SV-215391' do
  title 'The echo daemon must be disabled on AIX.'
  desc 'The echo service can be used in Denial of Service or SMURF attacks. It can also be used by someone else to get through a firewall or start a data storm. The echo service is unnecessary and it increases the attack vector of the system.'
  desc 'check', 'Check the /etc/inetd.conf for TCP and UDP echo service entries using command: 
# grep echo /etc/inetd.conf | grep -v \\# 

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "echo" entries by running commands: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'echo' -p 'tcp'
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'echo' -p 'udp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16589r294624_chk'
  tag severity: 'medium'
  tag gid: 'V-215391'
  tag rid: 'SV-215391r508663_rule'
  tag stig_id: 'AIX7-00-003086'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16587r294625_fix'
  tag 'documentable'
  tag legacy: ['SV-101511', 'V-91413']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
