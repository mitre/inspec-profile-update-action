control 'SV-225018' do
  title 'The Deny log on locally user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems and from unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on locally" user right defines accounts that are prevented from logging on interactively.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the compromise of an entire domain.

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'This applies to member servers and standalone systems. A separate version applies to domain controllers.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on locally" user right, this is a finding.

Domain Systems Only:
- Enterprise Admins Group
- Domain Admins Group

All Systems:
- Guests Group

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If the following SIDs are not defined for the "SeDenyInteractiveLogonRight" user right, this is a finding.

Domain Systems Only:
S-1-5-root domain-519 (Enterprise Admins)
S-1-5-domain-512 (Domain Admins)

All Systems:
S-1-5-32-546 (Guests)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Deny log on locally" to include the following:

Domain Systems Only:
- Enterprise Admins Group
- Domain Admins Group

All Systems:
- Guests Group'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26709r465956_chk'
  tag severity: 'medium'
  tag gid: 'V-225018'
  tag rid: 'SV-225018r569186_rule'
  tag stig_id: 'WN16-MS-000400'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-26697r465957_fix'
  tag 'documentable'
  tag legacy: ['V-73771', 'SV-88435']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
