control 'SV-89687' do
  title 'The MQ Appliance network device must off-load audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. Using a syslog logging target, the MQ Appliance logs all audit records to the syslog. Logging may be set to the following logging levels in descending order of criticality: debug, info, notice, warn, error, alert, emerg. The default is notice. 

Off-loading is a common process in information systems with limited audit storage capacity.'
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

Ask the system admin to provide logs from syslog server and verify the MQ appliance is logging to the syslog server. 

If the logs are not off-loaded, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance CLI as a privileged user. 

To enter global configuration mode, enter "config". 

To create a syslog target, enter: 
logging target <logging target name> 
type syslog 
admin-state "enabled" 
local-address <MQ Appliance IP> 
remote-address <syslog server IP> 
remote-port <syslog server port> 
event audit debug 
event auth debug 
event mgmt debug 
event cli debug 
event user debug 
event system error 
exit 
write mem 
y

Configure the MQ appliance to off-load audit records to a remote syslog server.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74865r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75013'
  tag rid: 'SV-89687r1_rule'
  tag stig_id: 'MQMH-ND-001390'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-81641r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
