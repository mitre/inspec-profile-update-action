control 'SV-89659' do
  title 'The MQ Appliance network device must generate account activity alerts that are forwarded to the administrators and Information System Security Officer (ISSO). Activity includes, creation, removal, modification and re-enablement after being previously disabled.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply create a new account. Notification of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail that documents the creation of accounts and notifies administrators and ISSOs. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes. 

Using a syslog logging target, the MQ Appliance logs audit events, including when accounts are created. Logging may be set to the following logging levels in descending order of criticality: debug, info, notice, warn, error, alert, emerg. The default is notice. 

It is the responsibility of the sysadmin to configure the triggers necessary to send alerts based upon information received at the syslog server. To meet the current requirement, the sysadmin must configure trigger notifications upon receiving the following audit events in the syslog server: 0x8240001f and 0x810001f0. Changes to access and/or privilege parameters will fall into this event category.

'
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

Ask the system admin to provide evidence that alerts are sent based on the following audit events: 0x8240001f and 0x810001f0. 

Account administration events will fall into this event category and be written to the audit logs. 

If alerts are not sent when accounts on the MQ appliance are created, modified, deleted, or re-enabled, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance CLI as a privileged user. 

To enter global configuration mode, enter "config". 

To creates a syslog target, enter: 
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

Configure alerts that will trigger off of syslog audit events: 0x8240001f and 0x810001f0.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74837r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74985'
  tag rid: 'SV-89659r1_rule'
  tag stig_id: 'MQMH-ND-000840'
  tag gtitle: 'SRG-APP-000291-NDM-000275'
  tag fix_id: 'F-81601r1_fix'
  tag satisfies: ['SRG-APP-000291-NDM-000275', 'SRG-APP-000292-NDM-000276', 'SRG-APP-000293-NDM-000277', 'SRG-APP-000294-NDM-000278', 'SRG-APP-000319-NDM-000283', 'SRG-APP-000320-NDM-000284']
  tag 'documentable'
  tag cci: ['CCI-001683', 'CCI-001684', 'CCI-001685', 'CCI-001686', 'CCI-002130', 'CCI-002132']
  tag nist: ['AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)']
end
