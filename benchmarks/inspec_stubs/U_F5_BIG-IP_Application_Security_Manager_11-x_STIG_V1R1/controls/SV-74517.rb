control 'SV-74517' do
  title 'The BIG-IP ASM module must be configured to handle invalid inputs in a predictable and documented manner that reflects organizational and system objectives.'
  desc 'A common vulnerability of network elements is unpredictable behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notifying the appropriate personnel, creating an audit record, and rejecting invalid input.

This requirement applies to gateways and firewalls that perform content inspection or have higher layer proxy functions.'
  desc 'check', 'Verify the BIG-IP ASM module is configured to handle invalid inputs in a predictable and documented manner that reflects organizational and system objectives.

This can be demonstrated by the SA sending an invalid input to a virtual server.  Provide evidence that the virtual server was able to handle the invalid input and maintain operation.

If the BIG-IP ASM module is not configured to handle invalid inputs in a predictable and documented manner that reflects organizational and system objectives, this is a finding.'
  desc 'fix', 'Configure the BIG-IP ASM module to handle invalid inputs in a predictable and documented manner that reflects organizational and system objectives.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP ASM 11.x'
  tag check_id: 'C-60849r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60087'
  tag rid: 'SV-74517r1_rule'
  tag stig_id: 'F5BI-AS-000229'
  tag gtitle: 'SRG-NET-000380-ALG-000128'
  tag fix_id: 'F-65581r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
