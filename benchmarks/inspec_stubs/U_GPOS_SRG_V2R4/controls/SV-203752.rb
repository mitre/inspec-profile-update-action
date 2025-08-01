control 'SV-203752' do
  title 'The operating system must behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.'
  desc 'A common vulnerability of operating system is unpredictable behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.'
  desc 'check', 'Verify the operating system behaves in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3877r375377_chk'
  tag severity: 'medium'
  tag gid: 'V-203752'
  tag rid: 'SV-203752r380203_rule'
  tag stig_id: 'SRG-OS-000432-GPOS-00191'
  tag gtitle: 'SRG-OS-000432'
  tag fix_id: 'F-3877r375378_fix'
  tag 'documentable'
  tag legacy: ['V-56727', 'SV-70987']
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
