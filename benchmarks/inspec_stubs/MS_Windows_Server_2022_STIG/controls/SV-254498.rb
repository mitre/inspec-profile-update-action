control 'SV-254498' do
  title 'Windows Server 2022 create permanent shared objects user right must not be assigned to any groups or accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Create permanent shared objects" user right could expose sensitive data by creating shared objects.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Create permanent shared objects" user right, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs are granted the "SeCreatePermanentPrivilege" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Create permanent shared objects to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57983r849308_chk'
  tag severity: 'medium'
  tag gid: 'V-254498'
  tag rid: 'SV-254498r877392_rule'
  tag stig_id: 'WN22-UR-000080'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-57934r849309_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
