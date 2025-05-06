control 'SV-225005' do
  title 'The Enable computer and user accounts to be trusted for delegation user right must only be assigned to the Administrators group on domain controllers.'
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
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26696r465917_chk'
  tag severity: 'medium'
  tag gid: 'V-225005'
  tag rid: 'SV-225005r569186_rule'
  tag stig_id: 'WN16-DC-000420'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-26684r465918_fix'
  tag 'documentable'
  tag legacy: ['SV-88441', 'V-73777']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
