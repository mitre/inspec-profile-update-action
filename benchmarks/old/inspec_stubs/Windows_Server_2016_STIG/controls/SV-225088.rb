control 'SV-225088' do
  title 'The Perform volume maintenance tasks user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Perform volume maintenance tasks" user right can manage volume and disk configurations. This could be used to delete volumes, resulting in data loss or a denial of service.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If an application requires this user right, this is not a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeManageVolumePrivilege" user right, this is a finding.

S-1-5-32-544 (Administrators)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Perform volume maintenance tasks to include only the following accounts or groups:

- Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26779r891712_chk'
  tag severity: 'medium'
  tag gid: 'V-225088'
  tag rid: 'SV-225088r891712_rule'
  tag stig_id: 'WN16-UR-000280'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-26767r890516_fix'
  tag 'documentable'
  tag legacy: ['SV-88461', 'V-73797']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
