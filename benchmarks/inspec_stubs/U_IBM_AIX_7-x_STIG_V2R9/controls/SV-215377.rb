control 'SV-215377' do
  title 'The discard daemon must be disabled on AIX.'
  desc 'The discard service is used as a debugging and measurement tool. It sets up a listening socket and ignores data that it receives. This is a /dev/null service and is obsolete. This can be used in DoS attacks and therefore, must be disabled to prevent attacks.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^discard[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "discard" entries by running commands: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'discard' -p 'tcp' 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'discard' -p 'udp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16575r294582_chk'
  tag severity: 'medium'
  tag gid: 'V-215377'
  tag rid: 'SV-215377r508663_rule'
  tag stig_id: 'AIX7-00-003072'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16573r294583_fix'
  tag 'documentable'
  tag legacy: ['V-91383', 'SV-101481']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
