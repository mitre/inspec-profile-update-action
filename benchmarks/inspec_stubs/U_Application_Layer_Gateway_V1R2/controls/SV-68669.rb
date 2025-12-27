control 'SV-68669' do
  title 'The ALG must produce audit records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack. In order to compile an accurate risk assessment and provide forensic analysis, security personnel need to know the source of the event.

In addition to logging where events occur within the network, the audit records must also identify sources of events such as IP addresses, processes, and node or device names.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the ALG produces audit records containing information to establish the source of the events.

If the ALG does not produce audit records containing information to establish the source of the events, this is a finding.'
  desc 'fix', 'Configure the ALG to produce audit records containing information to establish the source of the events.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55039r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54423'
  tag rid: 'SV-68669r1_rule'
  tag stig_id: 'SRG-NET-000077-ALG-000046'
  tag gtitle: 'SRG-NET-000077-ALG-000046'
  tag fix_id: 'F-59277r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
