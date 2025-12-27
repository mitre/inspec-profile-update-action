control 'SV-89685' do
  title 'The MQ Appliance network device must generate audit records for all account creations, modifications, disabling, and termination events.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Using a syslog logging target, the MQ Appliance logs all audit events, including account creations, modifications, disabling, and termination events. Logging may be set to the following logging levels in descending order of criticality: debug, info, notice, warn, error, alert, emerg. The default is notice. 

Audit records can be generated from various components within the MQ Appliance network device (e.g., module or policy filter).'
  desc 'check', 'Log on to the MQ Appliance CLI as a privileged user. 

Enter: 
co 
show logging target 

All configured logging targets will be displayed. Verify: 
- This list includes a remote syslog notification target; and 
- It includes all desired log event source and log level parameters, e.g., event audit info. 

In the WebGUI, Manage Appliance/User access. Create, disable or modify an account. Verify the administrator receives notification of this event. 

If any is not true, this is a finding.'
  desc 'fix', 'Configure a syslog target by using the command line interface (CLI). Log on as an administrative user. 

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

It is the responsibility of the sysadmin to configure the triggers necessary to send alerts based upon information received at the syslog server. To meet the current requirement, the sysadmin should trigger notification upon receiving the following audit events: 0x8240001f and 0x810001f0. All account creations, modifications, disabling, and termination events fall into this event category.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74863r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75011'
  tag rid: 'SV-89685r1_rule'
  tag stig_id: 'MQMH-ND-001380'
  tag gtitle: 'SRG-APP-000509-NDM-000324'
  tag fix_id: 'F-81627r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
