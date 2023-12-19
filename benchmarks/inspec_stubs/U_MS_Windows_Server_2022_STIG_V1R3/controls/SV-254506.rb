control 'SV-254506' do
  title 'Windows Server 2022 lock pages in memory user right must not be assigned to any groups or accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Lock pages in memory" user right allows physical memory to be assigned to processes, which could cause performance issues or a denial of service.

'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Lock pages in memory" user right, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs are granted the "SeLockMemoryPrivilege" user right, this is a finding.

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the Information System Security Officer (ISSO).

The application account must meet requirements for application account passwords, such as length (WN22-00-000050) and required frequency of changes (WN22-00-000060).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Lock pages in memory to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57991r849332_chk'
  tag severity: 'medium'
  tag gid: 'V-254506'
  tag rid: 'SV-254506r877392_rule'
  tag stig_id: 'WN22-UR-000160'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-57942r849333_fix'
  tag satisfies: ['SRG-OS-000324-GPOS-00125', 'SRG-OS-000433-GPOS-00193']
  tag 'documentable'
  tag cci: ['CCI-002235', 'CCI-002824']
  tag nist: ['AC-6 (10)', 'SI-16']
end
