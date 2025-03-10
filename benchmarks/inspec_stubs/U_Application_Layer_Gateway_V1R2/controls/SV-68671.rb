control 'SV-68671' do
  title 'The ALG must produce audit records containing information to establish the outcome of the events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the network.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the network after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the ALG produces audit records containing information to establish the outcome of the events.

If the ALG does not produce audit records containing information to establish the outcome of the events, this is a finding.'
  desc 'fix', 'Configure the ALG to produce audit records containing information to establish the outcome of the events.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55041r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54425'
  tag rid: 'SV-68671r1_rule'
  tag stig_id: 'SRG-NET-000078-ALG-000047'
  tag gtitle: 'SRG-NET-000078-ALG-000047'
  tag fix_id: 'F-59279r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
