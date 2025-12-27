control 'SV-109149' do
  title 'The Central Log Server must produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit record content that may be necessary to satisfy the requirement of this policy includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server produces audit records containing information to establish what type of events occurred.

If the Central Log Server is not configured to produce audit records containing information to establish what type of events occurred, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to produce audit records containing information to establish what type of events occurred.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-98895r1_chk'
  tag severity: 'low'
  tag gid: 'V-100045'
  tag rid: 'SV-109149r1_rule'
  tag stig_id: 'SRG-APP-000095-AU-000680'
  tag gtitle: 'SRG-APP-000095-AU-000680'
  tag fix_id: 'F-105729r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
