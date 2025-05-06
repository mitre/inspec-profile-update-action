control 'SV-31264' do
  title 'Password/passcode maximum failed attempts must be set to the required value.'
  desc 'A hacker with unlimited attempts can determine the passcode of a smartphone within a few minutes using password hacking tools, which could lead to unauthorized access to the PDA/smartphone and disclosure of sensitive DoD data.'
  desc 'check', 'Check a sample (3-4 devices) of site PDAs and verify the PDA has been configured to wipe after 10 (or less) incorrect passwords have been entered.'
  desc 'fix', 'Set password/passcode maximum failed attempts to 10 or less.'
  impact 0.5
  ref 'DPMS Target PDA/PED'
  tag check_id: 'C-31672r1_chk'
  tag severity: 'medium'
  tag gid: 'V-25011'
  tag rid: 'SV-31264r1_rule'
  tag stig_id: 'WIR-MOS-PDA-017'
  tag gtitle: 'Password/passcode maximum failed attempts'
  tag fix_id: 'F-27662r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1'
end
