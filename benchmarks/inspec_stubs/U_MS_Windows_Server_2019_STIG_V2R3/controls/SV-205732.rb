control 'SV-205732' do
  title 'Windows Server 2019 Deny log on through Remote Desktop Services user right on domain controllers must be configured to prevent unauthenticated access.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on through Remote Desktop Services" user right defines the accounts that are prevented from logging on using Remote Desktop Services.

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'This applies to domain controllers. A separate version applies to other systems.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on through Remote Desktop Services" user right, this is a finding:

- Guests Group

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If the following SID(s) are not defined for the "SeDenyRemoteInteractiveLogonRight" user right, this is a finding.

S-1-5-32-546 (Guests)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Deny log on through Remote Desktop Services" to include the following:

- Guests Group'
  impact 0.5
  ref 'DPMS Target Windows Server 2019'
  tag check_id: 'C-5997r355114_chk'
  tag severity: 'medium'
  tag gid: 'V-205732'
  tag rid: 'SV-205732r569188_rule'
  tag stig_id: 'WN19-DC-000410'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-5997r355115_fix'
  tag 'documentable'
  tag legacy: ['SV-103051', 'V-92963']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
