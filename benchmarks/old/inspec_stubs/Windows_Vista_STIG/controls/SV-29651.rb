control 'SV-29651' do
  title 'The password history must be configured to 24 passwords remembered.'
  desc 'A system is more vulnerable to unauthorized access when system users recycle the same password several times without being required to change a password to a unique password on a regularly scheduled basis. This enables users to effectively negate the purpose of mandating periodic password changes. The default value is 24 for Windows domain systems.  DoD has decided this is the appropriate value for all Windows systems.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> "Enforce password history" to "24" passwords remembered.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-1107'
  tag rid: 'SV-29651r2_rule'
  tag gtitle: 'Password Uniqueness'
  tag fix_id: 'F-74855r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
