control 'SV-215376' do
  title 'The chargen daemon must be disabled on AIX.'
  desc 'This service is used to test the integrity of TCP/IP packets arriving at the destination.

This chargen service is a character generator service and is used for testing the integrity of TCP/IP packets arriving at the destination. An attacker may spoof packets between machines running the chargen service and thus provide an opportunity for DoS attacks. Disable this service to prevent attacks unless testing the network.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^chargen[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "chargen" entries by running commands: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'chargen' -p 'tcp' 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'chargen' -p 'udp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16574r294579_chk'
  tag severity: 'medium'
  tag gid: 'V-215376'
  tag rid: 'SV-215376r508663_rule'
  tag stig_id: 'AIX7-00-003071'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16572r294580_fix'
  tag 'documentable'
  tag legacy: ['SV-101479', 'V-91381']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
