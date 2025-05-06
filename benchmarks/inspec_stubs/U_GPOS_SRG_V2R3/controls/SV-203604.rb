control 'SV-203604' do
  title 'The operating system must produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what type of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the operating system audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.'
  desc 'check', 'Verify the operating system produces audit records containing information to establish what type of events occurred. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to produce audit records containing information to establish what type of events occurred.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3729r557068_chk'
  tag severity: 'medium'
  tag gid: 'V-203604'
  tag rid: 'SV-203604r557070_rule'
  tag stig_id: 'SRG-OS-000037-GPOS-00015'
  tag gtitle: 'SRG-OS-000037'
  tag fix_id: 'F-3729r557069_fix'
  tag 'documentable'
  tag legacy: ['SV-70907', 'V-56647']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
