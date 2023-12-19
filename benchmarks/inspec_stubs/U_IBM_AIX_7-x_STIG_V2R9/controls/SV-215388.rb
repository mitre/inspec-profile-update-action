control 'SV-215388' do
  title 'The pop3 daemon must be disabled on AIX.'
  desc 'The pop3 service provides a pop3 server. It supports the pop3 remote mail access protocol. It works with sendmail and bellmail. This service should be disabled if it is not required to prevent attacks.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^pop3[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "pop3" entry by running command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'pop3' -p 'tcp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16586r294615_chk'
  tag severity: 'medium'
  tag gid: 'V-215388'
  tag rid: 'SV-215388r508663_rule'
  tag stig_id: 'AIX7-00-003083'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16584r294616_fix'
  tag 'documentable'
  tag legacy: ['V-91407', 'SV-101505']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
