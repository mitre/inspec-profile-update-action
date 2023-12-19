control 'SV-29684' do
  title 'The built-in Windows password complexity policy must be enabled.'
  desc 'The use of complex passwords increases their strength against attack. The built-in Windows password complexity policy requires passwords to contain at least 3 of the 4 types of characters (numbers, upper- and lower-case letters, and special characters), as well as preventing the inclusion of user names or parts of.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> "Password must meet complexity requirements" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-1150'
  tag rid: 'SV-29684r2_rule'
  tag gtitle: 'Microsoft Strong Password Filtering'
  tag fix_id: 'F-71577r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-001619']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)']
end
