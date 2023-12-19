control 'SV-88287' do
  title 'Windows Server 2016 built-in administrator account must be renamed.'
  desc 'The built-in administrator account is a well-known account subject to attack. Renaming this account to an unidentified name improves the protection of this account and the system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Accounts: Rename administrator account" is not set to a value other than "Administrator", this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt

If "NewAdministratorName" is not something other than "Administrator" in the file, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Accounts: Rename administrator account" to a name other than "Administrator".'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-91457r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73623'
  tag rid: 'SV-88287r2_rule'
  tag stig_id: 'WN16-SO-000030'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-80073r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
