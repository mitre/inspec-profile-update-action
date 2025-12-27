control 'SV-86073' do
  title 'The CA API Gateway must behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.'
  desc 'A common vulnerability of network elements is unpredictable behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.

The CA API Gateway must validate both XML and JSON schemas to verify valid inputs from a client requesting Registered Services. This helps to prevent XDoS attacks and parameter tampering, which in turn helps to prevent the injection of malicious scripts or content into the request.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click all Registered Services required to validate inputs. 

Verify that either the "Validate XML Schema" or "Validate JSON Schema" Assertions have been added to the policies and that they have been configured in accordance with organizational requirements. 

If they have not, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click each of the Registered Services required to validate inputs that do not include a "Validate XML Schema" or Validate JSON Schema" Assertion. 

Add either the "Validate XML Schema" or "Validate JSON Schema" Assertion and configure in accordance with organizational requirements.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71839r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71449'
  tag rid: 'SV-86073r1_rule'
  tag stig_id: 'CAGW-GW-000710'
  tag gtitle: 'SRG-NET-000380-ALG-000128'
  tag fix_id: 'F-77767r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
