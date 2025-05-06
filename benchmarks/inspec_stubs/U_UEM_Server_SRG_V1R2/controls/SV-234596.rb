control 'SV-234596' do
  title 'The UEM server must be configured to write to the server event log when invalid inputs are received.'
  desc 'A common vulnerability of applications is unpredictable behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input. 

Satisfies:FPT_TST_EXT.1.2'
  desc 'check', 'Verify the UEM server writes to the server event log when invalid inputs are received.

If the UEM server does not write to the server event log when invalid inputs are received, this is a finding.'
  desc 'fix', 'Configure the UEM server to write to the server event log when invalid inputs are received.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37781r615422_chk'
  tag severity: 'medium'
  tag gid: 'V-234596'
  tag rid: 'SV-234596r879818_rule'
  tag stig_id: 'SRG-APP-000447-UEM-000321'
  tag gtitle: 'SRG-APP-000447'
  tag fix_id: 'F-37746r615423_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
