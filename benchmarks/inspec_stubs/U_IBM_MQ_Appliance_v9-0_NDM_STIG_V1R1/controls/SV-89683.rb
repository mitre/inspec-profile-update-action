control 'SV-89683' do
  title 'The MQ Appliance network device must generate audit records when concurrent logons from different workstations occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Using a syslog logging target, the MQ Appliance logs all logons to the device-, including the source, time and date, and identity of the user. Logging may be set to the following logging levels in descending order of criticality: debug, info, notice, warn, error, alert, emerg. The default is notice. 

Audit records can be generated from various components within the MQ Appliance network device (e.g., module or policy filter). 

It is the responsibility of the sysadmin to configure the triggers necessary to send alerts based upon information received at the syslog server. The sysadmin can trigger notifications upon receiving the following audit event: 0x81000033. This is the logon event.'
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

Log onto the MQ appliance from two different workstations simultaneously. 

Request a copy of the audit logs and verify both events were recorded in the logs. 

If log events were not created, this is a finding.'
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
y'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74861r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75009'
  tag rid: 'SV-89683r1_rule'
  tag stig_id: 'MQMH-ND-001370'
  tag gtitle: 'SRG-APP-000506-NDM-000323'
  tag fix_id: 'F-81625r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
