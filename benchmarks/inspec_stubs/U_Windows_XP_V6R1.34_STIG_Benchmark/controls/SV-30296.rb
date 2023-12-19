control 'SV-30296' do
  title 'IPv6 will be disabled until a deliberate transition strategy has been implemented.'
  desc 'Any nodes’ interface with IPv6 enabled by default presents a potential risk of traffic being transmitted or received without proper risk mitigation strategy and therefore a serious security concern.'
  desc 'fix', 'Uninstall the IPv6 protocol until a deliberate transition strategy has been implemented.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-14262'
  tag rid: 'SV-30296r1_rule'
  tag gtitle: 'IPv6 Transition'
  tag fix_id: 'F-27324r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
