control 'SV-215406' do
  title 'The rwalld daemon must be disabled on AIX.'
  desc 'The rwalld service allows remote users to broadcast system wide messages. The service runs as root and should be disabled unless absolutely necessary to prevent attacks.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^rwalld[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "rwalld" entry by running command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'rwalld' -p 'udp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16604r294669_chk'
  tag severity: 'medium'
  tag gid: 'V-215406'
  tag rid: 'SV-215406r508663_rule'
  tag stig_id: 'AIX7-00-003105'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16602r294670_fix'
  tag 'documentable'
  tag legacy: ['SV-101491', 'V-91393']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
