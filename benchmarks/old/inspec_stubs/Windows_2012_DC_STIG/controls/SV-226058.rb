control 'SV-226058' do
  title 'The reset period for the account lockout counter must be configured to 15 minutes or greater on Windows 2012.'
  desc 'The account lockout feature, when enabled, prevents brute-force password attacks on the system.  This parameter specifies the period of time that must pass after failed logon attempts before the counter is reset to "0".  The smaller this value is, the less effective the account lockout feature will be in protecting the local system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

If the "Reset account lockout counter after" value is less than "15" minutes, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> "Reset account lockout counter after" to at least "15" minutes.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27760r475497_chk'
  tag severity: 'medium'
  tag gid: 'V-226058'
  tag rid: 'SV-226058r852055_rule'
  tag stig_id: 'WN12-AC-000003'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-27748r475498_fix'
  tag 'documentable'
  tag legacy: ['SV-52849', 'V-1098']
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
