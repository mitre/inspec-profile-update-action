control 'SV-218581' do
  title 'The SNMP service must require the use of a FIPS 140-2 approved encryption algorithm for protecting the privacy of SNMP messages.'
  desc 'The SNMP service must use AES or a FIPS 140-2 approved successor algorithm for protecting the privacy of communications.'
  desc 'check', "Verify the SNMP daemon uses AES for SNMPv3 users.

Procedure:
Examine the default install location /etc/snmp/snmpd.conf
or:
# find / -name snmpd.conf 

# grep -v '^#' <snmpd.conf file> | grep -i createuser | grep -vi AES

If any line is present this is a finding."
  desc 'fix', 'Edit /etc/snmp/snmpd.conf and add the AES keyword for any create user statement without one.

Restart the SNMP service.
# service snmpd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20056r555941_chk'
  tag severity: 'medium'
  tag gid: 'V-218581'
  tag rid: 'SV-218581r603259_rule'
  tag stig_id: 'GEN005307'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-20054r555942_fix'
  tag 'documentable'
  tag legacy: ['V-22449', 'SV-63415']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
