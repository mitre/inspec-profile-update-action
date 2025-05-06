control 'SV-70987' do
  title 'The operating system must behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.'
  desc 'A common vulnerability of operating system is unpredictable behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.'
  desc 'check', 'Verify the operating system behaves in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57297r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56727'
  tag rid: 'SV-70987r1_rule'
  tag stig_id: 'SRG-OS-000432-GPOS-00191'
  tag gtitle: 'SRG-OS-000432-GPOS-00191'
  tag fix_id: 'F-61623r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
