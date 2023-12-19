control 'SV-29643' do
  title 'Windows 2008 account lockout duration must be configured to 15 minutes or greater.'
  desc 'The account lockout feature, when enabled, prevents brute-force password attacks on the system. This parameter specifies the period of time that an account will remain locked after the specified number of failed logon attempts.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Account Policies >> Account Lockout Policy.

If the "Account lockout duration" is less than "15" minutes (excluding "0"), this is a finding.

Configuring this to "0", requiring an administrator to unlock the account, is more restrictive and is not a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> "Account lockout duration" to "15" minutes or greater.

A value of "0" is also acceptable, requiring an administrator to unlock the account.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-74319r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1099'
  tag rid: 'SV-29643r2_rule'
  tag gtitle: 'Lockout Duration'
  tag fix_id: 'F-80989r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
