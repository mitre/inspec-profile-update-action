control 'SV-215373' do
  title 'The time daemon must be disabled on AIX.'
  desc 'This service can be used to synchronize system clocks.

The time service is an obsolete process used to synchronize system clocks at boot time. This has been superseded by NTP, which should be used if time synchronization is necessary. Unless required the time service must be disabled.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^time[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "time" entries by running commands: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'time' -p 'udp' 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'time' -p 'tcp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16571r294570_chk'
  tag severity: 'medium'
  tag gid: 'V-215373'
  tag rid: 'SV-215373r508663_rule'
  tag stig_id: 'AIX7-00-003068'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16569r294571_fix'
  tag 'documentable'
  tag legacy: ['V-91375', 'SV-101473']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
