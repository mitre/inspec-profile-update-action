control 'SV-88409' do
  title 'The Create a pagefile user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Create a pagefile" user right can change the size of a pagefile, which could affect system performance.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Create a pagefile" user right, this is a finding.

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeCreatePagefilePrivilege" user right, this is a finding.

S-1-5-32-544 (Administrators)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create a pagefile" to include only the following accounts or groups:

- Administrators'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-91477r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73745'
  tag rid: 'SV-88409r2_rule'
  tag stig_id: 'WN16-UR-000080'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-80195r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
