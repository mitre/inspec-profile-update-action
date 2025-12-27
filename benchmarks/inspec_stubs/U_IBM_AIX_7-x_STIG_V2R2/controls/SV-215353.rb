control 'SV-215353' do
  title 'If sendmail is not required on AIX, the sendmail service must be disabled.'
  desc 'The sendmail service has many historical vulnerabilities and, where possible, should be disabled. If the system is not required to operate as a mail server i.e. sending, receiving or processing e-mail, disable the sendmail daemon.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^start[[:blank:]]/usr/lib/sendmail" /etc/rc.tcpip

If the above command produces any output, this is a finding.'
  desc 'fix', 'In "/etc/rc.tcpip", comment out the "sendmail" entry by running command: 
# chrctcp -d sendmail'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16551r294510_chk'
  tag severity: 'medium'
  tag gid: 'V-215353'
  tag rid: 'SV-215353r508663_rule'
  tag stig_id: 'AIX7-00-003047'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16549r294511_fix'
  tag 'documentable'
  tag legacy: ['V-91331', 'SV-101429']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
