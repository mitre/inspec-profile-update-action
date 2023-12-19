control 'SV-215375' do
  title 'The ntalk daemon must be disabled on AIX.'
  desc 'This service establishes a two-way communication link between two users, either locally or remotely. Unless required the ntalk service will be disabled to prevent attacks.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^ntalk[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "ntalk" entry by running command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'ntalk' -p 'udp'

Restart inetd:
# refresh -s inetd)
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16573r294576_chk'
  tag severity: 'high'
  tag gid: 'V-215375'
  tag rid: 'SV-215375r508663_rule'
  tag stig_id: 'AIX7-00-003070'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16571r294577_fix'
  tag 'documentable'
  tag legacy: ['V-91379', 'SV-101477']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
