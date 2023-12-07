control 'SV-205629' do
  title 'Windows Server 2019 must have the number of allowed bad logon attempts configured to three or less.'
  desc 'The account lockout feature, when enabled, prevents brute-force password attacks on the system. The higher this value is, the less effective the account lockout feature will be in protecting the local system. The number of bad logon attempts must be reasonably small to minimize the possibility of a successful password attack while allowing for honest errors made during normal user logon.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

If the "Account lockout threshold" is "0" or more than "3" attempts, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt

If "LockoutBadCount" equals "0" or is greater than "3" in the file, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> "Account lockout threshold" to "3" or fewer invalid logon attempts (excluding "0", which is unacceptable).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-5894r354805_chk'
  tag severity: 'medium'
  tag gid: 'V-205629'
  tag rid: 'SV-205629r569188_rule'
  tag stig_id: 'WN19-AC-000020'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-5894r354806_fix'
  tag 'documentable'
  tag legacy: ['V-93141', 'SV-103229']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
