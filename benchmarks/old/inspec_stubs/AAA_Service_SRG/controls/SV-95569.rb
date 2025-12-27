control 'SV-95569' do
  title 'AAA Services configuration audit records must identify when (date and time) the events occurred.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know when events occurred (date and time). 

Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
  desc 'check', 'Verify AAA Services configuration audit records identify the date and time events occurred.

If AAA Services configuration audit records do not identify when the events occurred, this is a finding.'
  desc 'fix', 'Configure AAA Services audit records to identify when the events occurred by specifying the date and time.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80595r3_chk'
  tag severity: 'medium'
  tag gid: 'V-80859'
  tag rid: 'SV-95569r1_rule'
  tag stig_id: 'SRG-APP-000096-AAA-000230'
  tag gtitle: 'SRG-APP-000096-AAA-000230'
  tag fix_id: 'F-87713r4_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
