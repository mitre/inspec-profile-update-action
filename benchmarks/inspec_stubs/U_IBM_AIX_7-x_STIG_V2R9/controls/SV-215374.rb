control 'SV-215374' do
  title 'The talk daemon must be disabled on AIX.'
  desc 'This talk service is used to establish an interactive two-way communication link between two UNIX users. Unless required the talk service will be disabled to prevent attacks.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^talk[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "talkd" entry by running command:
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'talk' -p 'udp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16572r294573_chk'
  tag severity: 'medium'
  tag gid: 'V-215374'
  tag rid: 'SV-215374r508663_rule'
  tag stig_id: 'AIX7-00-003069'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16570r294574_fix'
  tag 'documentable'
  tag legacy: ['SV-101475', 'V-91377']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
