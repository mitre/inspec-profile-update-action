control 'SV-80791' do
  title 'The HP FlexFabric switch must be configured to send SNMP traps and notifications to the SNMP manager for the purpose of sending alarms and notifying appropriate personnel as required by specific events.'
  desc 'If appropriate actions are not taken when a network device failure occurs, a denial of service condition may occur which could result in mission failure since the network would be operating without a critical security monitoring and prevention function. Upon detecting a failure of network device security components, the HP FlexFabric Switch must activate a system alert message, send an alarm, or shut down. By immediately displaying an alarm message, potential security violations can be identified more quickly even when administrators are not logged on to the device. This can be facilitated by the switch sending SNMP traps to the SNMP manager that can then have the necessary action taken by automatic or operator intervention.'
  desc 'check', 'Determine if the HP FlexFabric Switch is configured to send system alert messages, alarms to a SNMP agent and/or automatically shuts down when a component failure is detected.

[HP] display current-configuration

snmp-agent
 snmp-agent local-engineid 800063A280D07E28ECBDB800000001
 snmp-agent sys-info version v3
 snmp-agent group v3 group1 privacy
 snmp-agent target-host trap address udp-domain 192.168.16.103 params securityname snmp1 v3 privacy
 snmp-agent usm-user v3 user1 group1 cipher authentication-mode sha $c$3$3C41avdWWmRMT64buQYb6FLdhVIUpAVHhIGyxIMhX6o3Qe3+GjY= privacy-mode aes128 $c$3$YpvVDasCitD9iCUvGc01ycckCq0rY+c6sThoqny+TjMTlQ==

If the HP FlexFabric Switch is not configured to send system alert messages and alarms to a SNMP agent and/or does not automatically shuts down when a component failure is detected, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to send system alert messages and alarms to a SNMP agent:

[HP]snmp-agent
[HP]snmp-agent sys-info version v3
[HP]snmp-agent group v3 group1 privacy
[HP]snmp-agent target-host trap address udp-domain 192.168.16.103 params securityname snmp1 v3 privacy
[HP]snmp-agent usm-user v3 user1 group1 simple authentication-mode xxxxxxxxx privacy-mode aes128 xxxxxxxxx'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66947r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66301'
  tag rid: 'SV-80791r1_rule'
  tag stig_id: 'HFFS-ND-000143'
  tag gtitle: 'SRG-APP-000516-NDM-000341'
  tag fix_id: 'F-72377r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
