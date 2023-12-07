control 'SV-48027' do
  title 'The reset period for the account lockout counter must be configured to 15 minutes or greater on Windows 8.'
  desc 'The account lockout feature, when enabled, prevents brute-force password attacks on the system.  This parameter specifies the period of time that must pass after failed logon attempts before the counter is reset to "0".  The smaller this value is, the less effective the account lockout feature will be in protecting the local system.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Account Policies >> Account Lockout Policy.

If the "Reset account lockout counter after" value is less than "15" minutes, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> "Reset account lockout counter after" to at least "15" minutes.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-74311r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1098'
  tag rid: 'SV-48027r2_rule'
  tag stig_id: 'WN08-AC-000003'
  tag gtitle: 'Bad Logon Counter Reset'
  tag fix_id: 'F-80979r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
