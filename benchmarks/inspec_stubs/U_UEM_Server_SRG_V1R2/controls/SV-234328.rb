control 'SV-234328' do
  title 'The UEM server must be configured to produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit record content that may be necessary to satisfy the requirement of this policy includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application. 

Satisfies:FAU_GEN.1.2(1) 
Reference:PP-MDM-412060'
  desc 'check', 'Verify the UEM server produces audit records containing information to establish what type of events occurred.

If the UEM server does not produce audit records containing information to establish what type of events occurred, this is a finding.'
  desc 'fix', 'Configure the UEM server to be configured to produce audit records containing information to establish what type of events occurred.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37513r613994_chk'
  tag severity: 'medium'
  tag gid: 'V-234328'
  tag rid: 'SV-234328r879563_rule'
  tag stig_id: 'SRG-APP-000095-UEM-000055'
  tag gtitle: 'SRG-APP-000095'
  tag fix_id: 'F-37478r613995_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
