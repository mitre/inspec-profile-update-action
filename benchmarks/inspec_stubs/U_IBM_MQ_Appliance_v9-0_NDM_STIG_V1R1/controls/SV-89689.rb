control 'SV-89689' do
  title 'The MQ Appliance network device must use automated mechanisms to alert security personnel to threats identified by authoritative sources (e.g., CTOs) and in association with CJCSM 6510.01B.'
  desc 'By immediately displaying an alarm message, potential security violations can be identified more quickly even when administrators are not logged into the MQ Appliance network device. An example of a mechanism to facilitate this would be through the use of SNMP traps. 

Using a syslog logging target, the MQ Appliance logs all audit and system events. Logging may be set to the following logging levels in descending order of criticality: debug, info, notice, warn, error, alert, emerg. The default is notice.

It is the responsibility of the sysadmin to configure the triggers necessary to send alerts based upon information received at the syslog server.'
  desc 'check', 'Log on to the MQ Appliance CLI as a privileged user. 

Enter: 
co 
show logging target 

All configured logging targets will be displayed. Verify: 
- This list includes a remote syslog notification target; and 
- It includes all desired log event source and log level parameters: 
event audit info 
event auth notice 
event mgmt notice 
event cli notice 
event user notice 
event system error 

Ask the system admin to provide evidence the required alert triggers have been set up. 

If any is not true, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance CLI as a privileged user. 

To enter global configuration mode, enter "config". 

To create a syslog target, enter: 
logging target <logging target name> 
type syslog 
admin-state enabled 
local-address <MQ Appliance IP> 
remote-address <syslog server IP> 
remote-port <syslog server port> 
event audit info 
event auth notice 
event mgmt notice 
event cli notice 
event user notice 
event system error 
exit 
write mem 
y 

It is the responsibility of the sysadmin to configure the triggers necessary to send alerts based upon information received at the syslog server. To meet the current requirement, the sysadmin must specify threat event patterns that should trigger alerts. Then, the sysadmin must configure alerts that will occur in response to those event patterns. Ideas for trigger event patterns can be gained from an examination of the existing syslog.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74867r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75015'
  tag rid: 'SV-89689r1_rule'
  tag stig_id: 'MQMH-ND-001420'
  tag gtitle: 'SRG-APP-000516-NDM-000333'
  tag fix_id: 'F-81629r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001274']
  tag nist: ['CM-6 b', 'SI-4 (12)']
end
