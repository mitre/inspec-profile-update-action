control 'SV-254512' do
  title 'Windows Server 2022 take ownership of files or other objects user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Take ownership of files or other objects" user right can take ownership of objects and make changes.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Take ownership of files or other objects" user right, this is a finding:

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeTakeOwnershipPrivilege" user right, this is a finding:

S-1-5-32-544 (Administrators)

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the Information System Security Officer (ISSO).

The application account must meet requirements for application account passwords, such as length (WN22-00-000050) and required frequency of changes (WN22-00-000060).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Take ownership of files or other objects to include only the following accounts or groups:

- Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57997r849350_chk'
  tag severity: 'medium'
  tag gid: 'V-254512'
  tag rid: 'SV-254512r877392_rule'
  tag stig_id: 'WN22-UR-000220'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-57948r849351_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
