control 'SV-225077' do
  title 'The Create permanent shared objects user right must not be assigned to any groups or accounts.'
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
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create permanent shared objects" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26768r466132_chk'
  tag severity: 'medium'
  tag gid: 'V-225077'
  tag rid: 'SV-225077r877392_rule'
  tag stig_id: 'WN16-UR-000110'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-26756r466133_fix'
  tag 'documentable'
  tag legacy: ['SV-88415', 'V-73751']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
