control 'SV-68893' do
  title 'The ALG must behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.'
  desc 'A common vulnerability of network elements is unpredictable behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.

This requirement applies to gateways and firewalls that perform content inspection or have higher-layer proxy functions.'
  desc 'check', 'Verify the ALG behaves in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.

If the ALG does not behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received, this is a finding.'
  desc 'fix', 'Configure the ALG to behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55267r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54647'
  tag rid: 'SV-68893r1_rule'
  tag stig_id: 'SRG-NET-000380-ALG-000128'
  tag gtitle: 'SRG-NET-000380-ALG-000128'
  tag fix_id: 'F-59503r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
