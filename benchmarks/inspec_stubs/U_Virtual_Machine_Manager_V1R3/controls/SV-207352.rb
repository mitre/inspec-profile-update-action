control 'SV-207352' do
  title 'The VMM must produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what types of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack. 

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process/VM identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the VMM audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured VMM.'
  desc 'check', 'Verify the VMM produces audit records containing information to establish what type of events occurred. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to produce audit records containing information to establish what type of events occurred.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7609r365466_chk'
  tag severity: 'medium'
  tag gid: 'V-207352'
  tag rid: 'SV-207352r378616_rule'
  tag stig_id: 'SRG-OS-000037-VMM-000150'
  tag gtitle: 'SRG-OS-000037'
  tag fix_id: 'F-7609r365467_fix'
  tag 'documentable'
  tag legacy: ['SV-71135', 'V-56875']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
