control 'SV-18391' do
  title 'User rights and advanced user rights settings do not meet minimum requirements.'
  desc 'Inappropriate granting of user and advanced user rights can provide system, administrative, and other high level capabilities not required by the normal user.'
  desc 'fix', 'Configure the system to prevent accounts from having unauthorized User Rights.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-1103'
  tag rid: 'SV-18391r2_rule'
  tag gtitle: 'User Rights Assignments'
  tag fix_id: 'F-5747r1_fix'
  tag potential_impacts: 'Arbitrarily removing application accounts from certain User Rights may cause the applications to cease functioning.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECLP-1'
end
