control 'SV-45952' do
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
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43241r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22449'
  tag rid: 'SV-45952r1_rule'
  tag stig_id: 'GEN005307'
  tag gtitle: 'GEN005307'
  tag fix_id: 'F-39320r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
