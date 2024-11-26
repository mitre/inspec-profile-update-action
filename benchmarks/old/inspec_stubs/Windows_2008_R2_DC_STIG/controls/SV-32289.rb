control 'SV-32289' do
  title 'The minimum password age must be configured to at least 1 day.'
  desc 'Permitting passwords to be changed in immediate succession within the same day allows users to cycle passwords through their history database.  This enables users to effectively negate the purpose of mandating periodic password changes.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Account Policies >> Password Policy.

If the value for the "Minimum password age" is not at least "1" day, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> "Minimum password age" to at least "1" day.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-60979r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1105'
  tag rid: 'SV-32289r2_rule'
  tag gtitle: 'Minimum Password Age'
  tag fix_id: 'F-65709r2_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
