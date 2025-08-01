control 'SV-71047' do
  title 'The operating system must verify remote disconnection at the termination of nonlocal maintenance and diagnostic sessions, when used for nonlocal maintenance sessions.'
  desc 'If the remote connection is not closed and verified as closed, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Remote connections must be disconnected and verified as disconnected when nonlocal maintenance sessions have been terminated and are no longer available for use.'
  desc 'check', 'Verify the operating system verifies remote disconnection at the termination of nonlocal maintenance and diagnostic sessions, when used for nonlocal maintenance sessions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to verify remote disconnection at the termination of nonlocal maintenance and diagnostic sessions, when used for nonlocal maintenance sessions.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57357r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56787'
  tag rid: 'SV-71047r1_rule'
  tag stig_id: 'SRG-OS-000395-GPOS-00175'
  tag gtitle: 'SRG-OS-000395-GPOS-00175'
  tag fix_id: 'F-61683r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002891']
  tag nist: ['MA-4 (7)']
end
