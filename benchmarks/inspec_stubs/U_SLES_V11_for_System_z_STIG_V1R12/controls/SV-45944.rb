control 'SV-45944' do
  title 'The SNMP service must use only SNMPv3 or its successors.'
  desc 'SNMP Versions 1 and 2 are not considered secure. Without the strong authentication and privacy provided by the SNMP Version 3 User-based Security Model (USM), an attacker or other unauthorized users may gain access to detailed system management information and use the information to launch attacks against the system.'
  desc 'check', "Check the SNMP daemon is not configured to use the v1 or v2c security models.

Procedure:
Examine the default install location /etc/snmp/snmpd.conf
or:
# find / -name snmpd.conf 

# grep -E '(v1|v2c|community|com2sec)' <snmp.conf file> | grep -v '^#'
If any configuration is found, this is a finding."
  desc 'fix', 'Edit /etc/snmp/snmpd.conf and remove references to the "v1", "v2c", "community", or "com2sec". 
Restart the SNMP service.
# service snmpd restart'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43239r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22447'
  tag rid: 'SV-45944r1_rule'
  tag stig_id: 'GEN005305'
  tag gtitle: 'GEN005305'
  tag fix_id: 'F-39314r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001435']
  tag nist: ['AC-17 (8)']
end
