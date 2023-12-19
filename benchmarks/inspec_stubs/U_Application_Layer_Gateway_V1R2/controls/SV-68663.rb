control 'SV-68663' do
  title 'The ALG must produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the gateway logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the ALG produces audit records containing information to establish what type of events occurred.

If the ALG does not produce audit records containing information to establish what type of events occurred, this is a finding.'
  desc 'fix', 'Configure the ALG to produce audit records containing information to establish what type of events occurred.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55033r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54417'
  tag rid: 'SV-68663r1_rule'
  tag stig_id: 'SRG-NET-000074-ALG-000043'
  tag gtitle: 'SRG-NET-000074-ALG-000043'
  tag fix_id: 'F-59271r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
