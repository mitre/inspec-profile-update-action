control 'SV-88761' do
  title 'The Cisco IOS XE router must be configured to send SNMP traps and notifications to the SNMP manager for the purpose of sending alarms and notifying appropriate personnel as required by specific events.'
  desc 'If appropriate actions are not taken when a network device failure occurs, a denial of service condition may occur which could result in mission failure since the network would be operating without a critical security monitoring and prevention function. Upon detecting a failure of network device security components, the HP FlexFabric Switch must activate a system alert message, send an alarm, or shut down. By immediately displaying an alarm message, potential security violations can be identified more quickly even when administrators are not logged into the device. This can be facilitated by the switch sending SNMP traps to the SNMP manager that can then have the necessary action taken by automatic or operator intervention.'
  desc 'check', 'Verify that the Cisco IOS XE router is configured to send traps to the SNMP manager.

The SNMP configuration should contain commands similar to the example below:

snmp-server enable traps
snmp-server host x.x.x.x version 3 auth xxxxxxxxx
snmp-server user TRAP_NMS1 TRAP_GROUP  v3 encrypted auth sha AAAAPPPP  priv aes 128 EEEEPPPP

Note: In the example above, the following values are used hypothetically:

Username for SNMP Manager: TRAP_NMS1
Group for SNMP Manager: TRAP_GROUP  
User password for HMAC authentication: AAAAPPPP
User password for encryption: EEEEPPPP
AES key length: 128

If the router is not configured to send traps to the SNMP manager, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router to send traps to the SNMP manager.

The SNMP configuration should contain commands similar to the example below:

snmp-server enable traps
snmp-server host x.x.x.x version 3 auth xxxxxxxxx
snmp-server user TRAP_NMS1 TRAP_GROUP  v3 encrypted auth sha AAAAPPPP  priv aes 128 EEEEPPPP

Note: In the example above, the following values are used hypothetically:

Username for SNMP Manager: TRAP_NMS1
Group for SNMP Manager: TRAP_GROUP  
User password for HMAC authentication: AAAAPPPP
User password for encryption: EEEEPPPP
AES key length: 128'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74179r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74087'
  tag rid: 'SV-88761r2_rule'
  tag stig_id: 'CISR-ND-000143'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-80627r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
