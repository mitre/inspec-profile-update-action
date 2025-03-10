control 'SV-226056' do
  title 'Windows 2012 account lockout duration must be configured to 15 minutes or greater.'
  desc 'The account lockout feature, when enabled, prevents brute-force password attacks on the system. This parameter specifies the period of time that an account will remain locked after the specified number of failed logon attempts.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

If the "Account lockout duration" is less than "15" minutes (excluding "0"), this is a finding.

Configuring this to "0", requiring an administrator to unlock the account, is more restrictive and is not a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> "Account lockout duration" to "15" minutes or greater.

A value of "0" is also acceptable, requiring an administrator to unlock the account.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27758r475491_chk'
  tag severity: 'medium'
  tag gid: 'V-226056'
  tag rid: 'SV-226056r569184_rule'
  tag stig_id: 'WN12-AC-000001'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-27746r475492_fix'
  tag 'documentable'
  tag legacy: ['SV-52850', 'V-1099']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
