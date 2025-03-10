control 'SV-225089' do
  title 'The Profile single process user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Profile single process" user right can monitor non-system processes performance. An attacker could use this to identify processes to attack.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Profile single process" user right, this is a finding.

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeProfileSingleProcessPrivilege" user right, this is a finding.

S-1-5-32-544 (Administrators)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Profile single process" to include only the following accounts or groups:

- Administrators'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26780r466168_chk'
  tag severity: 'medium'
  tag gid: 'V-225089'
  tag rid: 'SV-225089r569186_rule'
  tag stig_id: 'WN16-UR-000290'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-26768r466169_fix'
  tag 'documentable'
  tag legacy: ['SV-88463', 'V-73799']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
