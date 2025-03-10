control 'SV-89611' do
  title 'The MQ Appliance network device must alert the Information System Security Officer (ISSO) and System Administrator (SA) (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. 

Using a syslog logging target, the MQ Appliance logs audit events, including audit processing failures. Logging may be set to the following logging levels in descending order of criticality: debug, info, notice, warn, error, alert, emerg. The default is notice. 

The MQ appliance is configured to create the event in the logs that will be used to send an alert. The alerting process must be performed by a third-party alerting utility, centralized log management, or SIEM.'
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

Configuring notification of events occurring at the external logging server is the responsibility of the administrator. 

Ask the system admin to provide evidence the required alert triggers for the following event codes: 0x80c0006a, 0x82400067, 0x00330034, 0x80400080 have been set up and the ISSO and SA at a minimum are alerted. 

If there is no evidence that alerts are sent in the event of an audit processing failure, this is a finding.'
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
y

At the syslog server, set up event notification triggers for the following event codes: 0x80c0006a, 0x82400067, 0x00330034, 0x80400080.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74795r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74937'
  tag rid: 'SV-89611r1_rule'
  tag stig_id: 'MQMH-ND-000340'
  tag gtitle: 'SRG-APP-000108-NDM-000232'
  tag fix_id: 'F-81553r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
