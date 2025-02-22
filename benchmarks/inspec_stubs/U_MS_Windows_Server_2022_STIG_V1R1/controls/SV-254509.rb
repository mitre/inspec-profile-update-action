control 'SV-254509' do
  title 'Windows Server 2022 perform volume maintenance tasks user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Perform volume maintenance tasks" user right can manage volume and disk configurations. This could be used to delete volumes, resulting in data loss or a denial of service.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Perform volume maintenance tasks" user right, this is a finding:

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeManageVolumePrivilege" user right, this is a finding:

S-1-5-32-544 (Administrators)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Perform volume maintenance tasks to include only the following accounts or groups:

- Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57994r849341_chk'
  tag severity: 'medium'
  tag gid: 'V-254509'
  tag rid: 'SV-254509r849343_rule'
  tag stig_id: 'WN22-UR-000190'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-57945r849342_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
