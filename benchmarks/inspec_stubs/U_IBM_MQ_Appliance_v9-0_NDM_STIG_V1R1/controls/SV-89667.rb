control 'SV-89667' do
  title 'The MQ Appliance network device must generate an immediate alert when allocated audit record storage volume reaches 75 percent of repository maximum audit record storage capacity.'
  desc "If security personnel are not notified immediately upon storage volume utilization reaching 75 percent, they are unable to plan for storage capacity expansion. This could lead to the loss of audit information. Note that while the MQ Appliance network device must generate the alert, notification may be done by a management server. 

At the syslog server, set up event notification triggers for the following event codes: 0x80c0006a, 0x82400067, 0x00330034, 0x80400080. 

Note: The above notifications will occur if there is an interruption in logging information being sent to its intended external logging target. Configuring notification of storage capacity events occurring at the external logging server (e.g., 75 percent capacity) is the responsibility of that server's server administrator.

"
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

Ask the system admin to provide evidence the following alert triggers have been set up:
0x80c0006a, 0x82400067, 0x00330034, 0x80400080. 

Verify alerts are immediately sent when syslog storage capacity reaches 75% of maximum audit record storage capacity.

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

At the syslog server, set up event notification triggers for the following event codes: 0x80c0006a, 0x82400067, 0x00330034, 0x80400080. 

Set up notifications to immediately alert when audit record storage utilization exceeds 75% of storage capacity.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74845r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74993'
  tag rid: 'SV-89667r1_rule'
  tag stig_id: 'MQMH-ND-001040'
  tag gtitle: 'SRG-APP-000359-NDM-000294'
  tag fix_id: 'F-81609r2_fix'
  tag satisfies: ['SRG-APP-000359-NDM-000294', 'SRG-APP-000360-NDM-000295']
  tag 'documentable'
  tag cci: ['CCI-001855', 'CCI-001858']
  tag nist: ['AU-5 (1)', 'AU-5 (2)']
end
