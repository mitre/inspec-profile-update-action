control 'SV-89657' do
  title 'The MQ Appliance network device must activate a system alert message, send an alarm, and/or automatically shut down when a component failure is detected.'
  desc "Predictable failure prevention requires organizational planning to address device failure issues. If components key to maintaining the device's security fail to function, the device could continue operating in an insecure state. 

If appropriate actions are not taken when an MQ Appliance network device failure occurs, a denial of service condition may occur, which could result in mission failure since the network would be operating without a critical security monitoring and prevention function. 

Upon detecting a failure of MQ Appliance network device security components, the MQ Appliance network device must activate a system alert message, send an alarm, or shut down. 

With failure notification enabled, an error report can be sent to a designated recipient or uploaded to a specific location after the appliance returns to service from an unscheduled outage. 

This error report can contain diagnostic details. Intrusion detection will provide a warning and restart in Fail-Safe mode. (See https://ibm.biz/Bd4NJ5)"
  desc 'check', 'Log on to the MQ Appliance CLI as a privileged user. 

Enter: 
failure-notification 
show failure-notification 

Examine the configured parameters to verify the current configuration, including the notification address. 

If the MQ Appliance is not configured to send an alert when a component failure is detected, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance CLI as a privileged user. 

Enter: 
co 
failure-notification 
admin-state enabled 
upload-report <on or off> 
location-id <String to identify the issuing device> 
use-smtp on 
protocol smtp 
email-address <destination notification email address> 
remote-address <remote SMTP server address> 
internal-state on 
ffdc packet-capture on 
ffdc event-log on 
ffdc memory-trace on 
always-on-startup on 
always-on-shutdown on 
report-history <Max. # of local error rpts to maintain> 
exit 
write mem 
y'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74835r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74983'
  tag rid: 'SV-89657r1_rule'
  tag stig_id: 'MQMH-ND-000830'
  tag gtitle: 'SRG-APP-000268-NDM-000274'
  tag fix_id: 'F-81599r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001328']
  tag nist: ['CM-6 b', 'SI-13 (4) (b)']
end
