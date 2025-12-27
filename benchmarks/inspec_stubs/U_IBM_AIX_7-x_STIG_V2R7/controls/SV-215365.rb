control 'SV-215365' do
  title 'If SNMP is not required on AIX, the snmpmibd daemon must be disabled.'
  desc 'The snmpmibd daemon is a dpi2 sub-agent which manages a number of MIB variables. If snmpd is not required, it is recommended that it is disabled.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^start[[:blank:]]/usr/sbin/snmpmibd" /etc/rc.tcpip

If there is any output from the command, this is a finding.'
  desc 'fix', 'In "/etc/rc.tcpip", comment out the "snmpmibd" entry by running command: 
# chrctcp -d snmpmibd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16563r294546_chk'
  tag severity: 'medium'
  tag gid: 'V-215365'
  tag rid: 'SV-215365r508663_rule'
  tag stig_id: 'AIX7-00-003060'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16561r294547_fix'
  tag 'documentable'
  tag legacy: ['SV-101457', 'V-91359']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
