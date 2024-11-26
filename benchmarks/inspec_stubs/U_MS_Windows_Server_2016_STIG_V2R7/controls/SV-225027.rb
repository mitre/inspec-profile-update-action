control 'SV-225027' do
  title 'Windows Server 2016 built-in guest account must be renamed.'
  desc 'The built-in guest account is a well-known user account on all Windows systems and, as initially installed, does not require a password. This can allow access to system resources by unauthorized users. Renaming this account to an unidentified name improves the protection of this account and the system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Accounts: Rename guest account" is not set to a value other than "Guest", this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt

If "NewGuestName" is not something other than "Guest" in the file, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Accounts: Rename guest account" to a name other than "Guest".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26718r465983_chk'
  tag severity: 'medium'
  tag gid: 'V-225027'
  tag rid: 'SV-225027r569186_rule'
  tag stig_id: 'WN16-SO-000040'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26706r465984_fix'
  tag 'documentable'
  tag legacy: ['SV-88289', 'V-73625']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
