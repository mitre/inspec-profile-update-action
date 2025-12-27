control 'SV-225020' do
  title 'The Enable computer and user accounts to be trusted for delegation user right must not be assigned to any groups or accounts on member servers.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Enable computer and user accounts to be trusted for delegation" user right allows the "Trusted for Delegation" setting to be changed. This could allow unauthorized users to impersonate other users.'
  desc 'check', 'This applies to member servers and standalone systems. A separate version applies to domain controllers.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Enable computer and user accounts to be trusted for delegation" user right, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs are granted the "SeEnableDelegationPrivilege" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Enable computer and user accounts to be trusted for delegation" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26711r465962_chk'
  tag severity: 'medium'
  tag gid: 'V-225020'
  tag rid: 'SV-225020r569186_rule'
  tag stig_id: 'WN16-MS-000420'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-26699r465963_fix'
  tag 'documentable'
  tag legacy: ['SV-88443', 'V-73779']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
