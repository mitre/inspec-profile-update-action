control 'SV-29233' do
  title 'The use of local accounts with blank passwords is not restricted to console logons only.'
  desc 'This is a Category 1 finding because no accounts with blank passwords should exist on a system.  The password policy should prevent this from occurring.  However, if a local account with a blank password does exist, enabling this setting will limit the account to local console logon only.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Accounts: Limit local account use of blank passwords to console logon only” to “Enabled”.'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag severity: 'high'
  tag gid: 'V-3344'
  tag rid: 'SV-29233r1_rule'
  tag gtitle: 'Limit Blank Passwords'
  tag fix_id: 'F-5788r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
