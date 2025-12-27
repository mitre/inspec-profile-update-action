control 'SV-224998' do
  title 'The Add workstations to domain user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Add workstations to domain" right may add computers to a domain. This could result in unapproved or incorrectly configured systems being added to a domain.'
  desc 'check', 'This applies to domain controllers. It is NA for other systems.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Add workstations to domain" right, this is a finding.

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeMachineAccountPrivilege" user right, this is a finding.

S-1-5-32-544 (Administrators)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Add workstations to domain" to include only the following accounts or groups:

- Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26689r465896_chk'
  tag severity: 'medium'
  tag gid: 'V-224998'
  tag rid: 'SV-224998r569186_rule'
  tag stig_id: 'WN16-DC-000350'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-26677r465897_fix'
  tag 'documentable'
  tag legacy: ['SV-88401', 'V-73737']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
