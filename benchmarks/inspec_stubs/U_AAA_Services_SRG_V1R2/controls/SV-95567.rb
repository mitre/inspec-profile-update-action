control 'SV-95567' do
  title 'AAA Services configuration audit records must identify what type of events occurred.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit record content that may be necessary to satisfy the requirement of this policy includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
  desc 'check', 'Verify AAA Services configuration audit records identify what type of events occurred.

If AAA Services configuration audit records do not identify what type of events occurred, this is a finding.'
  desc 'fix', 'Configure AAA Services audit records to identify what type of events occurred.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80593r3_chk'
  tag severity: 'medium'
  tag gid: 'V-80857'
  tag rid: 'SV-95567r1_rule'
  tag stig_id: 'SRG-APP-000095-AAA-000220'
  tag gtitle: 'SRG-APP-000095-AAA-000220'
  tag fix_id: 'F-87711r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
