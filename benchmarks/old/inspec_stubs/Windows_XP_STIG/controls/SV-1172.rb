control 'SV-1172' do
  title 'Users are not warned in advance that their passwords will expire.'
  desc 'This setting configures the system to display a warning to users telling them how many days are left before their password expires.  By giving the user advanced warning, the user has time to construct a sufficiently strong password.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Interactive Logon: Prompt user to change password before expiration” to “14” days or more.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-1172'
  tag rid: 'SV-1172r1_rule'
  tag gtitle: 'Password Expiration Warning'
  tag fix_id: 'F-114r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
