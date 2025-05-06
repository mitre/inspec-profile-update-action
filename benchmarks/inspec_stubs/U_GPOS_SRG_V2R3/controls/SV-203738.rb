control 'SV-203738' do
  title 'The operating system must verify remote disconnection at the termination of nonlocal maintenance and diagnostic sessions, when used for nonlocal maintenance sessions.'
  desc 'If the remote connection is not closed and verified as closed, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Remote connections must be disconnected and verified as disconnected when nonlocal maintenance sessions have been terminated and are no longer available for use.'
  desc 'check', 'Verify the operating system verifies remote disconnection at the termination of nonlocal maintenance and diagnostic sessions, when used for nonlocal maintenance sessions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to verify remote disconnection at the termination of nonlocal maintenance and diagnostic sessions, when used for nonlocal maintenance sessions.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3863r375278_chk'
  tag severity: 'medium'
  tag gid: 'V-203738'
  tag rid: 'SV-203738r379972_rule'
  tag stig_id: 'SRG-OS-000395-GPOS-00175'
  tag gtitle: 'SRG-OS-000395'
  tag fix_id: 'F-3863r375279_fix'
  tag 'documentable'
  tag legacy: ['V-56787', 'SV-71047']
  tag cci: ['CCI-002891']
  tag nist: ['MA-4 (7)']
end
