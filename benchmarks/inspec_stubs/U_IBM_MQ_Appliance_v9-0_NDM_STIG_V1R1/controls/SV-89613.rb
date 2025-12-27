control 'SV-89613' do
  title 'The MQ Appliance network device must back up audit records at least every seven days onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Regularly backing up audit records to a different system or onto separate media than the system being audited helps to assure, in the event of a catastrophic system failure, the audit records will be retained. This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records. 

Using a syslog logging target, the MQ Appliance logs audit events, including the continuous backup of audit records. Logging may be set to the following logging levels in descending order of criticality: debug, info, notice, warn, error, alert, emerg. The default is notice.'
  desc 'check', 'Log on to the MQ Appliance CLI as a privileged user. 

Enter: 
co 
show logging target 

All configured logging targets will be displayed. Verify: 
- This list of log targets includes an appropriate syslog notification target; 
- The log target is enabled; and 
- It includes all desired log event source and log level parameters, e.g., event audit debug. 

If any of these conditions is not true, this is a finding.'
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
  tag check_id: 'C-74797r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74939'
  tag rid: 'SV-89613r1_rule'
  tag stig_id: 'MQMH-ND-000430'
  tag gtitle: 'SRG-APP-000125-NDM-000241'
  tag fix_id: 'F-81555r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
