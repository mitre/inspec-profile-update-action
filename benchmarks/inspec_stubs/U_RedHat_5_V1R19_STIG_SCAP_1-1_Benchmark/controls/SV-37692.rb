control 'SV-37692' do
  title 'The SNMP service must use only SNMPv3 or its successors.'
  desc 'SNMP Versions 1 and 2 are not considered secure. Without the strong authentication and privacy provided by the SNMP Version 3 User-based Security Model (USM), an attacker or other unauthorized users may gain access to detailed system management information and use the information to launch attacks against the system.'
  desc 'fix', 'Edit /etc/snmpd.conf and remove references to the "v1", "v2c", "community", or "com2sec". 
Restart the SNMP service.
# service snmpd restart'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22447'
  tag rid: 'SV-37692r1_rule'
  tag stig_id: 'GEN005305'
  tag gtitle: 'GEN005305'
  tag fix_id: 'F-31966r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-001435']
  tag nist: ['AC-17 (8)']
end
