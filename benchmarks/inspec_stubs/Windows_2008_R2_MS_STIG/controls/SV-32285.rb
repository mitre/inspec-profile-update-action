control 'SV-32285' do
  title 'The reset period for the account lockout counter must be configured to 15 minutes or greater on Windows 2008 R2.'
  desc 'The account lockout feature, when enabled, prevents brute-force password attacks on the system. This parameter specifies the period of time that must pass after failed logon attempts before the counter is reset to "0". The smaller this value is, the less effective the account lockout feature will be in protecting the local system.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Account Policies >> Account Lockout Policy.

If the "Reset account lockout counter after" value is less than "15" minutes, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> "Reset account lockout counter after" to at least "15" minutes.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-74335r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1098'
  tag rid: 'SV-32285r3_rule'
  tag gtitle: 'Bad Logon Counter Reset'
  tag fix_id: 'F-81007r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
