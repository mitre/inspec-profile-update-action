control 'SV-215231' do
  title 'If SNMP service is enabled on AIX, the default SNMP password must not be used in the /etc/snmpd.conf config file.'
  desc 'Use default SNMP password increases the chance of security vulnerability on SNMP service.'
  desc 'check', 'Inspect "/etc/snmpd.conf" to find all the passwords that are used in the config file:

# grep -v "^#" /etc/snmpd.conf | grep -E "public|private|password"

If any results are returned, default passwords are being used and this is a finding.'
  desc 'fix', 'Edit "/etc/snmpd.conf" config file to remove or change all the default passwords that are used in the file.

Restart snmpd:
# stopsrc -s snmpd
# startsrc -s snmpd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16429r294144_chk'
  tag severity: 'medium'
  tag gid: 'V-215231'
  tag rid: 'SV-215231r508663_rule'
  tag stig_id: 'AIX7-00-001135'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16427r294145_fix'
  tag 'documentable'
  tag legacy: ['V-91583', 'SV-101681']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
