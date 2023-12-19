control 'SV-225024' do
  title 'Windows Server 2016 built-in guest account must be disabled.'
  desc 'A system faces an increased vulnerability threat if the built-in guest account is not disabled. This is a known account that exists on all Windows systems and cannot be deleted. This account is initialized during the installation of the operating system with no password assigned.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Accounts: Guest account status" is not set to "Disabled", this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt

If "EnableGuestAccount" equals "1" in the file, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Accounts: Guest account status" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26715r465974_chk'
  tag severity: 'medium'
  tag gid: 'V-225024'
  tag rid: 'SV-225024r569186_rule'
  tag stig_id: 'WN16-SO-000010'
  tag gtitle: 'SRG-OS-000121-GPOS-00062'
  tag fix_id: 'F-26703r465975_fix'
  tag 'documentable'
  tag legacy: ['SV-88475', 'V-73809']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
