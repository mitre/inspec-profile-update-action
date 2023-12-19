control 'SV-215381' do
  title 'The rusersd daemon must be disabled on AIX.'
  desc 'The rusersd service runs as root and provides a list of current users active on a system. An attacker may use this service to learn valid account names on the system. This is not an essential service and should be disabled.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^rusersd[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "rusersd" entry by running command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'rusersd' -p 'udp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16579r294594_chk'
  tag severity: 'medium'
  tag gid: 'V-215381'
  tag rid: 'SV-215381r508663_rule'
  tag stig_id: 'AIX7-00-003076'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16577r294595_fix'
  tag 'documentable'
  tag legacy: ['V-91391', 'SV-101489']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
