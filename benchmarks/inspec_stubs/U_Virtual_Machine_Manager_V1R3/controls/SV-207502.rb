control 'SV-207502' do
  title 'The VMM must behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.'
  desc 'A common vulnerability of VMM is unpredictable behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where VMM responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.'
  desc 'check', 'Verify the VMM behaves in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.

If it does not, this is a finding.'
  desc 'fix', 'Ensure the VMM behaves in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7759r365910_chk'
  tag severity: 'medium'
  tag gid: 'V-207502'
  tag rid: 'SV-207502r854676_rule'
  tag stig_id: 'SRG-OS-000432-VMM-001730'
  tag gtitle: 'SRG-OS-000432'
  tag fix_id: 'F-7759r365911_fix'
  tag 'documentable'
  tag legacy: ['SV-71565', 'V-57305']
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
