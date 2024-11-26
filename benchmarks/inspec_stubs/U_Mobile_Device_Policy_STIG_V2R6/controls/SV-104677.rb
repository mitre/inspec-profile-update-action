control 'SV-104677' do
  title 'Personally owned or contractor owned mobile devices must not be used to transmit, receive, store, or process DoD information or connect to DoD networks.'
  desc 'The use of unauthorized personally-owned CMDs to receive, store, process, or transmit DoD data could expose sensitive DoD data to unauthorized people. The DoD CIO currently prohibits the use of personally owned or contractor owned mobile devices (Bring Your Own Device – BYOD).'
  desc 'check', 'Interview the site IAM and IAO and determine if personally owned or contractor owned CMDs (Bring Your Own Device – BYOD) are used at the site to transmit, receive, store, or process DoD information or connect to DoD networks. 

Mark as a finding if personally owned or contractor owned CMDs (Bring Your Own Device – BYOD) are used to transmit, receive, store, or process DoD information or connect to DoD networks.'
  desc 'fix', 'Prohibit use of personally owned or contractor owned mobile devices (Bring Your Own Device – BYOD) at the site to transmit, receive, store, or process DoD information or connect to DoD networks.'
  impact 0.5
  ref 'DPMS Target Mobile Device Policy'
  tag check_id: 'C-94043r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94847'
  tag rid: 'SV-104677r1_rule'
  tag stig_id: 'WIR0010-01'
  tag gtitle: 'Personally-owned mobile devices (BYOD)'
  tag fix_id: 'F-100971r1_fix'
  tag 'documentable'
end
