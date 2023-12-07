control 'SV-205766' do
  title 'Windows Server 2019 Profile single process user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Profile single process" user right can monitor non-system processes performance. An attacker could use this to identify processes to attack.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Profile single process" user right, this is a finding:

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeProfileSingleProcessPrivilege" user right, this is a finding:

S-1-5-32-544 (Administrators)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Profile single process" to include only the following accounts or groups:

- Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-6031r355216_chk'
  tag severity: 'medium'
  tag gid: 'V-205766'
  tag rid: 'SV-205766r877392_rule'
  tag stig_id: 'WN19-UR-000200'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-6031r355217_fix'
  tag 'documentable'
  tag legacy: ['V-93083', 'SV-103171']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
