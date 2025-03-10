control 'SV-254445' do
  title 'Windows Server 2022 must have the built-in guest account disabled.'
  desc 'A system faces an increased vulnerability threat if the built-in guest account is not disabled. This is a known account that exists on all Windows systems and cannot be deleted. This account is initialized during the installation of the operating system with no password assigned.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Accounts: Guest account status" is not set to "Disabled", this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt

If "EnableGuestAccount" equals "1" in the file, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Accounts: Guest account status to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57930r849149_chk'
  tag severity: 'medium'
  tag gid: 'V-254445'
  tag rid: 'SV-254445r849151_rule'
  tag stig_id: 'WN22-SO-000010'
  tag gtitle: 'SRG-OS-000121-GPOS-00062'
  tag fix_id: 'F-57881r849150_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
