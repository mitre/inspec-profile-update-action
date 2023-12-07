control 'SV-225003' do
  title 'The Deny log on locally user right on domain controllers must be configured to prevent unauthenticated access.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on locally" user right defines accounts that are prevented from logging on interactively.

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'This applies to domain controllers. A separate version applies to other systems.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on locally" user right, this is a finding.

- Guests Group

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If the following SID(s) are not defined for the "SeDenyInteractiveLogonRight" user right, this is a finding.

S-1-5-32-546 (Guests)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Deny log on locally" to include the following:

- Guests Group'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26694r465911_chk'
  tag severity: 'medium'
  tag gid: 'V-225003'
  tag rid: 'SV-225003r569186_rule'
  tag stig_id: 'WN16-DC-000400'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-26682r465912_fix'
  tag 'documentable'
  tag legacy: ['V-73769', 'SV-88433']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
