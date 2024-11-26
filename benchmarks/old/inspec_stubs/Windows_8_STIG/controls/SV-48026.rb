control 'SV-48026' do
  title 'The number of allowed bad logon attempts must meet minimum requirements.'
  desc 'The account lockout feature, when enabled, prevents brute-force password attacks on the system.  The higher this value is, the less effective the account lockout feature will be in protecting the local system.  The number of bad logon attempts must be reasonably small to minimize the possibility of a successful password attack, while allowing for honest errors made during a normal user logon.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Account Policies -> Account Lockout Policy.

If the "Account lockout threshold" is "0" or more than 3 attempts, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy -> "Account lockout threshold" to "3" or less invalid logon attempts (excluding "0" which is unacceptable).'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44764r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1097'
  tag rid: 'SV-48026r1_rule'
  tag stig_id: 'WN08-AC-000002'
  tag gtitle: 'Bad Logon Attempts'
  tag fix_id: 'F-41164r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
