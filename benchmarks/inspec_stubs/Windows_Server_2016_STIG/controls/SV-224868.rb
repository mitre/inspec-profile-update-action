control 'SV-224868' do
  title 'Windows Server 2016 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater.'
  desc 'The account lockout feature, when enabled, prevents brute-force password attacks on the system. This parameter specifies the period of time that must pass after failed logon attempts before the counter is reset to "0". The smaller this value is, the less effective the account lockout feature will be in protecting the local system.

'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

If the "Reset account lockout counter after" value is less than "15" minutes, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt

If "ResetLockoutCount" is less than "15" in the file, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> "Reset account lockout counter after" to at least "15" minutes.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26559r465506_chk'
  tag severity: 'medium'
  tag gid: 'V-224868'
  tag rid: 'SV-224868r852302_rule'
  tag stig_id: 'WN16-AC-000030'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-26547r465507_fix'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag 'documentable'
  tag legacy: ['SV-87965', 'V-73313']
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
