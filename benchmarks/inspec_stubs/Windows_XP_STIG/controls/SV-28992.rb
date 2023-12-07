control 'SV-28992' do
  title 'Minimum password age does not meet minimum requirements.'
  desc 'Permitting passwords to be changed in immediate succession within the same day, allows users to cycle passwords through their history database.  This enables users to effectively negate the purpose of mandating periodic password changes.'
  desc 'fix', 'Configure the Minimum Password Age so that it is a minimum of "1".'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-1105'
  tag rid: 'SV-28992r1_rule'
  tag gtitle: 'Minimum Password Age'
  tag fix_id: 'F-6574r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-2, IAIA-1'
end
