control 'SV-225004' do
  title 'The Deny log on through Remote Desktop Services user right on domain controllers must be configured to prevent unauthenticated access.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on through Remote Desktop Services" user right defines the accounts that are prevented from logging on using Remote Desktop Services.

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'This applies to domain controllers. A separate version applies to other systems.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on through Remote Desktop Services" user right, this is a finding.

- Guests Group

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If the following SID(s) are not defined for the "SeDenyRemoteInteractiveLogonRight" user right, this is a finding.

S-1-5-32-546 (Guests)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Deny log on through Remote Desktop Services" to include the following:

- Guests Group'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26695r465914_chk'
  tag severity: 'medium'
  tag gid: 'V-225004'
  tag rid: 'SV-225004r569186_rule'
  tag stig_id: 'WN16-DC-000410'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-26683r465915_fix'
  tag 'documentable'
  tag legacy: ['SV-88437', 'V-73773']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
