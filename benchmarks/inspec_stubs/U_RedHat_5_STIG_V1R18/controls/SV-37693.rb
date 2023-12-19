control 'SV-37693' do
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
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36890r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22448'
  tag rid: 'SV-37693r1_rule'
  tag stig_id: 'GEN005306'
  tag gtitle: 'GEN005306'
  tag fix_id: 'F-31971r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
