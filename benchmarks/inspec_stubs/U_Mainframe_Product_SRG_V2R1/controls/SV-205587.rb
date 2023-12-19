control 'SV-205587' do
  title 'The Mainframe Product must behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.'
  desc 'A common vulnerability of applications is unpredictable behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.'
  desc 'check', 'If the Mainframe Product has no function or capability for user/data input, this is not applicable.

Examine installation and configuration settings.

If the Mainframe Product is not configured to behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5853r299988_chk'
  tag severity: 'medium'
  tag gid: 'V-205587'
  tag rid: 'SV-205587r851351_rule'
  tag stig_id: 'SRG-APP-000447-MFP-000332'
  tag gtitle: 'SRG-APP-000447'
  tag fix_id: 'F-5853r299989_fix'
  tag 'documentable'
  tag legacy: ['SV-82965', 'V-68475']
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
