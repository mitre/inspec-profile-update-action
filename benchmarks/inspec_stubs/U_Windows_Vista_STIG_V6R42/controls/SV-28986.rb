control 'SV-28986' do
  title 'Number of allowed bad-logon attempts does not meet minimum requirements.'
  desc 'The account lockout feature, when enabled, prevents brute-force password attacks on the system.  The higher this value is, the less effective the account lockout feature will be in protecting the local system.  The number of bad logon attempts should be reasonably small to minimize the possibility of a successful password attack, while allowing for honest errors made during a normal user logon.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Account Policies -> Account Lockout Policy.

If the “Account lockout threshold” is "0" or more than three attempts, then this is a finding.'
  desc 'fix', 'Configure the system to lock out an account after three invalid logon attempts.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-3200r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1097'
  tag rid: 'SV-28986r1_rule'
  tag gtitle: 'Bad Logon Attempts'
  tag fix_id: 'F-6569r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
