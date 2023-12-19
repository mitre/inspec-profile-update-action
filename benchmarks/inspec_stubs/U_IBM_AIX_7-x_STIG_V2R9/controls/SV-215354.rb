control 'SV-215354' do
  title 'If SNMP is not required on AIX, the snmpd service must be disabled.'
  desc 'The snmpd daemon is used by many 3rd party applications to monitor the health of the system. This allows remote monitoring of network and server configuration.

To prevent remote attacks this daemon should not be enabled unless there is no alternative.'
  desc 'check', 'Verify there is no "snmpd" service running on the AIX by doing the following:

From the command prompt, execute the following command: 

# grep "^start[[:blank:]]/usr/sbin/snmpd" /etc/rc.tcpip

If there is any output from the command, this is a finding.'
  desc 'fix', 'In "/etc/rc.tcpip", comment out the "snmpd" entry by running command: 
# chrctcp -d snmpd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16552r294513_chk'
  tag severity: 'medium'
  tag gid: 'V-215354'
  tag rid: 'SV-215354r508663_rule'
  tag stig_id: 'AIX7-00-003048'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16550r294514_fix'
  tag 'documentable'
  tag legacy: ['SV-101431', 'V-91333']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
