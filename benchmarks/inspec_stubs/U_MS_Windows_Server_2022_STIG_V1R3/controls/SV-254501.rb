control 'SV-254501' do
  title 'Windows Server 2022 force shutdown from a remote system user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Force shutdown from a remote system" user right can remotely shut down a system, which could result in a denial of service.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Force shutdown from a remote system" user right, this is a finding:

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeRemoteShutdownPrivilege" user right, this is a finding:

S-1-5-32-544 (Administrators)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Force shutdown from a remote system to include only the following accounts or groups:

- Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57986r849317_chk'
  tag severity: 'medium'
  tag gid: 'V-254501'
  tag rid: 'SV-254501r877392_rule'
  tag stig_id: 'WN22-UR-000110'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-57937r849318_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
