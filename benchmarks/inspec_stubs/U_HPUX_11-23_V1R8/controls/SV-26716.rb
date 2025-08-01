control 'SV-26716' do
  title 'The SNMP service must use only SNMPv3 or its successors.'
  desc 'SNMP Versions 1 and 2 are not considered secure. Without the strong authentication and privacy that is provided by the SNMP Version 3 User-based Security Model (USM), an attacker or other unauthorized users may gain access to detailed system management information and use that information to launch attacks against the system.'
  desc 'check', 'Verify the SNMP daemon is not configured to use community strings.
# cat /etc/SnmpAgent.d/snmpd.conf |egrep -i "get-community-name|set-community-name"

If any configuration is found, this is a finding.'
  desc 'fix', 'Edit /etc/SnmpAgent.d/snmpd.conf and remove references to get-community-name and set-community-name. Restart the SNMP service. 
# /sbin/init.d/SnmpMaster 

The snmpd script (/usr/sbin/snmpd) will take care of starting the subagents. It if does not, check the options in /etc/rc.config.d/SnmpMaster that influence the startup behavior.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36607r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22447'
  tag rid: 'SV-26716r1_rule'
  tag stig_id: 'GEN005305'
  tag gtitle: 'GEN005305'
  tag fix_id: 'F-31975r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-001435']
  tag nist: ['AC-17 (8)']
end
