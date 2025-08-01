control 'SV-218580' do
  title 'The SNMP service must require the use of a FIPS 140-2 approved cryptographic hash algorithm as part of its authentication and integrity methods.'
  desc 'The SNMP service must use SHA-1 or a FIPS 140-2 approved successor for authentication and integrity.'
  desc 'check', "Verify the SNMP daemon uses SHA for SNMPv3 users.

Procedure:
Examine the default install location /etc/snmp/snmpd.conf
or:
# find / -name snmpd.conf 

# grep -v '^#' <snmpd.conf file> | grep -i createuser | grep -vi SHA
If any line is present this is a finding."
  desc 'fix', 'Edit /etc/snmp/snmpd.conf and add the SHA keyword for any create user statement without one.

Restart the SNMP service.
# service snmpd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20055r555938_chk'
  tag severity: 'medium'
  tag gid: 'V-218580'
  tag rid: 'SV-218580r603259_rule'
  tag stig_id: 'GEN005306'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-20053r555939_fix'
  tag 'documentable'
  tag legacy: ['V-22448', 'SV-63407']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
