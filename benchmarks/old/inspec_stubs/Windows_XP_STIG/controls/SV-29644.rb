control 'SV-29644' do
  title 'Maximum password age does not meet minimum requirements.'
  desc 'The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the passwords.   Further, scheduled changing of passwords hinders the ability of unauthorized system users to crack passwords and gain access to a system.'
  desc 'fix', %q(Configure the Maximum Password Age so that it is not "0" and doesn't exceed 60 days.)
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-1104'
  tag rid: 'SV-29644r1_rule'
  tag gtitle: 'Maximum Password Age'
  tag fix_id: 'F-6573r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-2, IAIA-1'
end
