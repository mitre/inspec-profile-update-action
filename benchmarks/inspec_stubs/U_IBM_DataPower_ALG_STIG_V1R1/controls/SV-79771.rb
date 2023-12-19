control 'SV-79771' do
  title 'The DataPower Gateway must behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.'
  desc 'A common vulnerability of network elements is unpredictable behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.

This requirement applies to gateways and firewalls that perform content inspection or have higher-layer proxy functions.'
  desc 'check', 'Using the WebGUI, go to Objects >> XML Processing >> Matching Rule to verify there is a rule that defines the expected form of the incoming message. If there is no match, the message will be discarded. 

Go to Objects >> XML Processing >> Processing Rule to verify there are error rules that provide appropriate system responses to invalid and unexpected inputs.

If no error rules discarding invalid messages are configured, this is a finding.'
  desc 'fix', 'Using the WebGUI, go to Objects >> XML Processing >> Matching Rule to define a rule that defines the expected form of the incoming message. If there is no match, the message will be discarded. 

Go to Objects >> XML Processing >> Processing Rule to define error rules that provide appropriate system responses to invalid and unexpected inputs. Invalid messages must be discarded.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65909r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65281'
  tag rid: 'SV-79771r1_rule'
  tag stig_id: 'WSDP-AG-000106'
  tag gtitle: 'SRG-NET-000380-ALG-000128'
  tag fix_id: 'F-71221r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
