control 'SV-79563' do
  title 'The DataPower Gateway must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.'
  desc 'check', 'Administration >> Miscellaneous >> "Manage Log Targets" >> Click the appropriate log target (e.g., "SystemResourcesLog") >> Click the "Event Filters" tab >> Confirm subscriptions to the following event codes: 0x00330034, 0x01a40001, 0x01a30002, 0x01a30003, 0x01a40005, 0x01a30006, 0x01a30014, 0x01a30015, 0x01a30017. If any of these codes are not subscribed to, this is a finding.'
  desc 'fix', 'A Log Target can be configured to generate notifications (e.g., SNMP, SMTP) in the event that any of these event codes are detected.

Privileged account user log on to default domain >> Administration >> Miscellaneous >> "Manage Log Targets" >> Click the "Add" button >> Name: "SystemResourcesLog” >> Target Type: Select the desired notification mechanism (e.g., SMTP) >> Configure the SMTP server, providing the requested information; Log Format: “text” >> Fixed Format: off >> Rate Limit: “100” >> Feedback Detection: on >> Identical Event Detection: off >> Click the "Event Filters" tab >> Under "Event Subscriptions", add the following event codes: 0x00330034, 0x01a40001, 0x01a30002, 0x01a30003, 0x01a40005, 0x01a30006, 0x01a30014, 0x01a30015, 0x01a30017 >> Click the "Apply" button >> Click "Save Configuration".'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65699r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65073'
  tag rid: 'SV-79563r1_rule'
  tag stig_id: 'WSDP-NM-000033'
  tag gtitle: 'SRG-APP-000108-NDM-000232'
  tag fix_id: 'F-71013r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
