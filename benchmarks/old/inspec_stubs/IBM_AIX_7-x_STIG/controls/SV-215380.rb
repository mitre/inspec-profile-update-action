control 'SV-215380' do
  title 'The rstatd daemon must be disabled on AIX.'
  desc 'The rstatd service is used to provide kernel statistics and other monitorable parameters pertinent to the system such as: CPU usage, system uptime, network usage etc. An attacker may use this information in a DoS attack. This service should be disabled.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^rstatd[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "rstatd" entry by running command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'rstatd' -p 'udp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16578r294591_chk'
  tag severity: 'medium'
  tag gid: 'V-215380'
  tag rid: 'SV-215380r508663_rule'
  tag stig_id: 'AIX7-00-003075'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16576r294592_fix'
  tag 'documentable'
  tag legacy: ['SV-101487', 'V-91389']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
