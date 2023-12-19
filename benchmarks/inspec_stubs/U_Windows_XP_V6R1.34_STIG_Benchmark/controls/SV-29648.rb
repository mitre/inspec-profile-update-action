control 'SV-29648' do
  title 'Password uniqueness does not meet minimum requirements.'
  desc 'A system is more vulnerable to unauthorized access when system users recycle the same password several times without being required to change a password to a unique password on a regularly scheduled basis.  This enables users to effectively negate the purpose of mandating periodic password changes.'
  desc 'fix', 'Configure the system to remember a minimum of "24" used passwords.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-1107'
  tag rid: 'SV-29648r1_rule'
  tag gtitle: 'Password Uniqueness'
  tag fix_id: 'F-6576r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
end
