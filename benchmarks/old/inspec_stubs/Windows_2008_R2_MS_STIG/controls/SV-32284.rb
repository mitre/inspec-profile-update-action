control 'SV-32284' do
  title 'The system must lockout accounts after 3 invalid logon attempts within a specified time period.'
  desc 'The account lockout feature, when enabled, prevents brute-force password attacks on the system.  The higher this value is, the less effective the account lockout feature will be in protecting the local system.  The number of bad logon attempts should be reasonably small to minimize the possibility of a successful password attack, while allowing for honest errors made during a normal user logon.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Account Policies >> Account Lockout Policy.

If the "Account lockout threshold" is "0" or more than "3" attempts, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> "Account lockout threshold" to "3" or less invalid logon attempts (excluding "0", which is unacceptable).'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-60969r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1097'
  tag rid: 'SV-32284r2_rule'
  tag gtitle: 'Bad Logon Attempts'
  tag fix_id: 'F-65701r3_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
