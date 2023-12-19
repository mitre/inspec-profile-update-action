control 'SV-205745' do
  title 'Windows Server 2019 Enable computer and user accounts to be trusted for delegation user right must only be assigned to the Administrators group on domain controllers.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Enable computer and user accounts to be trusted for delegation" user right allows the "Trusted for Delegation" setting to be changed. This could allow unauthorized users to impersonate other users.'
  desc 'check', 'This applies to domain controllers. A separate version applies to other systems.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Enable computer and user accounts to be trusted for delegation" user right, this is a finding.

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeEnableDelegationPrivilege" user right, this is a finding.

S-1-5-32-544 (Administrators)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Enable computer and user accounts to be trusted for delegation" to include only the following accounts or groups:

- Administrators'
  impact 0.5
  ref 'DPMS Target MS Windows Server 2019'
  tag check_id: 'C-6010r355153_chk'
  tag severity: 'medium'
  tag gid: 'V-205745'
  tag rid: 'SV-205745r569188_rule'
  tag stig_id: 'WN19-DC-000420'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-6010r355154_fix'
  tag 'documentable'
  tag legacy: ['SV-103129', 'V-93041']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
