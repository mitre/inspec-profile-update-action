control 'SV-215371' do
  title 'The ttdbserver daemon must be disabled on AIX.'
  desc 'The ttdbserver service is the tool-talk database service for CDE. This service runs as root and should be disabled. Unless required the ttdbserver service will be disabled to prevent attacks.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^#ttdbserver[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "ttdbserver" entry by running command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'ttdbserver' -p 'sunrpc_tcp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16569r294564_chk'
  tag severity: 'medium'
  tag gid: 'V-215371'
  tag rid: 'SV-215371r508663_rule'
  tag stig_id: 'AIX7-00-003066'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16567r294565_fix'
  tag 'documentable'
  tag legacy: ['SV-101469', 'V-91371']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
