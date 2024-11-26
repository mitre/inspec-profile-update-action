control 'SV-89607' do
  title 'The MQ Appliance network device must notify the administrator of changes to access and/or privilege parameters of the administrator account that occurred since the last logon.'
  desc 'Providing administrators with information regarding security-related changes to their account allows them to determine if any unauthorized activity has occurred. Changes to the account could be an indication of the account being compromised. Hence, without notification to the administrator, the compromise could go undetected if other controls were not in place to mitigate this risk. 

Using a syslog logging target, the MQ Appliance logs all changes to access or privilege parameters. Logging may be set to the following logging levels in descending order of criticality: debug, info, notice, warn, error, alert, emerg. The default is notice.

It is the responsibility of the sysadmin to configure the triggers necessary to send alerts based upon information received at the syslog server. To meet the requirement, the sysadmin must trigger notification upon receiving the following audit event: 0x8240001f. Changes to access and/or privilege parameters will fall into this event category. Ask the admin to provide evidence these alerts are configured.'
  desc 'check', 'Log on to the MQ Appliance CLI as a privileged user. 

Enter: 
co 
show logging target 

All configured logging targets will be displayed. Verify: 
- This list includes a remote syslog notification target; and 
- It includes all of the following log event source and log-level parameters: 
event audit info 
event auth notice 
event mgmt notice 
event cli notice 
event user notice 
event system error 

In the WebGUI, Administration (gear icon) >> Access >> User Account, add a user. 

Verify the administrator receives notification of this event. 

If the event notifications are not configured, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance CLI as a privileged user. 

Configure a syslog target by using the command line interface (CLI). 

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
  tag check_id: 'C-74791r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74933'
  tag rid: 'SV-89607r1_rule'
  tag stig_id: 'MQMH-ND-000200'
  tag gtitle: 'SRG-APP-000079-NDM-000219'
  tag fix_id: 'F-81549r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001395']
  tag nist: ['CM-6 b', 'AC-9 (3)']
end
