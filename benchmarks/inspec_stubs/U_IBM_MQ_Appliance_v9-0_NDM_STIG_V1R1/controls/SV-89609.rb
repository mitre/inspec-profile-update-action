control 'SV-89609' do
  title 'The MQ Appliance network device must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.'
  desc 'This requirement supports non-repudiation of actions taken by an administrator and is required in order to maintain the integrity of the configuration management process. All configuration changes to the MQ Appliance network device are logged, and administrators authenticate with two-factor authentication before gaining administrative access. Together, these processes will ensure the administrators can be held accountable for the configuration changes they implement. 

Using a syslog logging target, the MQ Appliance logs configuration changes to the device. Logging may be set to the following logging levels in descending order of criticality: debug, info, notice, warn, error, alert, emerg. The default is notice.

'
  desc 'check', 'Log on to the MQ Appliance CLI as a privileged user. 

Enter: 
co 
show logging target 

All configured logging targets will be displayed. Verify: 
- This list includes a remote syslog notification target; and 
- It includes all of the following log event source and log level parameters: 
event audit info 
event auth notice 
event mgmt notice 
event cli notice 
event user notice 
event system error 

If these events are not configured, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance CLI as a privileged user. 

Configure a syslog target. 

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
y'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74793r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74935'
  tag rid: 'SV-89609r1_rule'
  tag stig_id: 'MQMH-ND-000210'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag fix_id: 'F-81551r1_fix'
  tag satisfies: ['SRG-APP-000080-NDM-000220', 'SRG-APP-000095-NDM-000225', 'SRG-APP-000097-NDM-000227', 'SRG-APP-000098-NDM-000228', 'SRG-APP-000100-NDM-000230', 'SRG-APP-000319-NDM-000283']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000132', 'CCI-000133', 'CCI-000166', 'CCI-001487', 'CCI-002130']
  tag nist: ['AU-3 a', 'AU-3 c', 'AU-3 d', 'AU-10', 'AU-3 f', 'AC-2 (4)']
end
