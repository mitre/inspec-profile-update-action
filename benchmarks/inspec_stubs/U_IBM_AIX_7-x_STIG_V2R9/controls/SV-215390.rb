control 'SV-215390' do
  title 'The instsrv daemon must be disabled on AIX.'
  desc 'The instsrv service is part of the Network Installation Tools, used for servicing servers running AIX 3.2. This service should be disabled to prevent attacks.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^instsrv[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "instsrv" entry by running command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'instsrv' -p 'tcp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16588r294621_chk'
  tag severity: 'medium'
  tag gid: 'V-215390'
  tag rid: 'SV-215390r508663_rule'
  tag stig_id: 'AIX7-00-003085'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16586r294622_fix'
  tag 'documentable'
  tag legacy: ['V-91411', 'SV-101509']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
