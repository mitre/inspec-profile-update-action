control 'SV-79699' do
  title 'The DataPower Gateway must send an alert to, at a minimum, the ISSO and SCA when an audit processing failure occurs.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Possible audit processing failures also include the inability of ALG to write to the central audit log.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations, (i.e., all audit data storage repositories combined), or both.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Administration >> Miscellaneous >> "Manage Log Targets" >> Click the appropriate log target (e.g., "logTargetSystemResources" >> Click the "Event Filters" tab >> Confirm subscriptions to the following event codes: 0x00330034, 0x01a40001, 0x01a30002, 0x01a30003, 0x01a40005, 0x01a30006, 0x01a30014, 0x01a30015, 0x01a30017. 

If any of these codes are not subscribed to, this is a finding.'
  desc 'fix', 'Audit logging may be interrupted due to insufficient memory and/or insufficient disk space to write logs. IBM DataPower Gateway appliances will monitor system resources and generate appropriate event codes in such cases. The relevant event codes are: 0x00330034, 0x01a40001, 0x01a30002, 0x01a30003, 0x01a40005, 0x01a30006, 0x01a30014, 0x01a30015, 0x01a30017 (Privileged account user log on to default domain >> Administration >> Debug >> "View List of Event Codes").

A Log Target can be configured to generate notifications (e.g., SNMP, SMTP) in the event that any of these event codes are detected.

Privileged account user log on to default domain >> Administration >> Miscellaneous >> "Manage Log Targets" >> Click the "Add" button >> Name: "logTargetSystemResources" >> Target Type: select the desired notification mechanism (e.g., SNMP, SMTP) >> Log Format: Select a desired log format (e.g., text) >> Fixed Format: off >> Rate Limit: Specify an alert rate limit (default is 100/second) >> Feedback Detection: on >> Identical Event Detection: off >> Provide any additional required configuration specific to the Target Type (e.g., SMTP) >> Click the "Event Filters" tab >> Under "Event Subscriptions", add the following event codes: 0x00330034, 0x01a40001, 0x01a30002, 0x01a30003, 0x01a40005, 0x01a30006, 0x01a30014, 0x01a30015, 0x01a30017 >> Click the "Apply" button >> Click "Save Configuration".'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65837r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65209'
  tag rid: 'SV-79699r1_rule'
  tag stig_id: 'WSDP-AG-000026'
  tag gtitle: 'SRG-NET-000088-ALG-000054'
  tag fix_id: 'F-71149r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
