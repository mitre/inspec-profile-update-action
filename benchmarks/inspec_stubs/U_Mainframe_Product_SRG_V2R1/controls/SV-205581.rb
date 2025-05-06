control 'SV-205581' do
  title 'Mainframe Products must verify remote disconnection at the termination of nonlocal maintenance and diagnostic sessions.'
  desc 'If the remote connection is not closed and verified as closed, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Remote connections must be disconnected and verified as disconnected when nonlocal maintenance sessions have been terminated and are no longer available for use.'
  desc 'check', 'If the Mainframe Product has no function or capability for nonlocal maintenance, this is not applicable.

Examine installation and configuration settings.

If the Mainframe Product does not verify remote disconnection at the termination of nonlocal maintenance and diagnostic sessions, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to verify remote disconnection at the termination of nonlocal maintenance and diagnostic sessions.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5847r299970_chk'
  tag severity: 'medium'
  tag gid: 'V-205581'
  tag rid: 'SV-205581r851347_rule'
  tag stig_id: 'SRG-APP-000413-MFP-000262'
  tag gtitle: 'SRG-APP-000413'
  tag fix_id: 'F-5847r299971_fix'
  tag 'documentable'
  tag legacy: ['SV-82917', 'V-68427']
  tag cci: ['CCI-002891']
  tag nist: ['MA-4 (7)']
end
