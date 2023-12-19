control 'SV-254287' do
  title 'Windows Server 2022 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater.'
  desc 'The account lockout feature, when enabled, prevents brute-force password attacks on the system. This parameter specifies the period of time that must pass after failed logon attempts before the counter is reset to "0". The smaller this value is, the less effective the account lockout feature will be in protecting the local system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

If the "Reset account lockout counter after" value is less than "15" minutes, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt

If "ResetLockoutCount" is less than "15" in the file, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> Reset account lockout counter after to at least "15" minutes.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57772r848675_chk'
  tag severity: 'medium'
  tag gid: 'V-254287'
  tag rid: 'SV-254287r848677_rule'
  tag stig_id: 'WN22-AC-000030'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-57723r848676_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
