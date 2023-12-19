control 'SV-234556' do
  title 'The UEM server must verify remote disconnection when non-local maintenance and diagnostic sessions are terminated.'
  desc 'If the remote connection is not closed and verified as closed, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Remote connections must be disconnected and verified as disconnected when non-local maintenance sessions have been terminated and are no longer available for use.'
  desc 'check', 'Verify the UEM server verifies remote disconnection when non-local maintenance and diagnostic sessions are terminated.

If the UEM server does not verify remote disconnection when non-local maintenance and diagnostic sessions are terminated, this is a finding.'
  desc 'fix', 'Configure the UEM server to verify remote disconnection when non-local maintenance and diagnostic sessions are terminated.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37741r615993_chk'
  tag severity: 'medium'
  tag gid: 'V-234556'
  tag rid: 'SV-234556r617355_rule'
  tag stig_id: 'SRG-APP-000413-UEM-000284'
  tag gtitle: 'SRG-APP-000413'
  tag fix_id: 'F-37706r615312_fix'
  tag 'documentable'
  tag cci: ['CCI-002891']
  tag nist: ['MA-4 (7)']
end
