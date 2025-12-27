control 'SV-95469' do
  title 'The SDN controller must be configured to produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack. Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the network element logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured network element.'
  desc 'check', 'Review the SDN controller configuration to determine if the audit records will note the type of event that is being logged. 

If the SDN controller is not configured to produce audit records containing information to establish what type of events occurred, this is a finding.'
  desc 'fix', 'Configure the SDN controller to include the type of event in the log records.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80495r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80759'
  tag rid: 'SV-95469r1_rule'
  tag stig_id: 'SRG-NET-000074-SDN-000120'
  tag gtitle: 'SRG-NET-000074'
  tag fix_id: 'F-87613r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
