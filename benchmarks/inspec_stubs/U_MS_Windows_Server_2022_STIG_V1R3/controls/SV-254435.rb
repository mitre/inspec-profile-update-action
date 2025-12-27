control 'SV-254435' do
  title 'Windows Server 2022 Deny access to this computer from the network user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and local accounts and from unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny access to this computer from the network" user right defines the accounts that are prevented from logging on from the network.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the compromise of an entire domain.

Local accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'This applies to member servers and standalone or nondomain-joined systems. A separate version applies to domain controllers.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny access to this computer from the network" user right, this is a finding:

Domain Systems Only:
- Enterprise Admins group
- Domain Admins group
- "Local account and member of Administrators group" or "Local account" (see Note below)

All Systems:
- Guests group

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If the following SIDs are not defined for the "SeDenyNetworkLogonRight" user right, this is a finding.

Domain Systems Only:
S-1-5-root domain-519 (Enterprise Admins)
S-1-5-domain-512 (Domain Admins)
S-1-5-114 ("Local account and member of Administrators group") or S-1-5-113 ("Local account")

All Systems:
S-1-5-32-546 (Guests)

Note: These are built-in security groups. "Local account" is more restrictive but may cause issues on servers such as systems that provide failover clustering.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Deny access to this computer from the network to include the following:

Domain Systems Only:
- Enterprise Admins group
- Domain Admins group
- "Local account and member of Administrators group" or "Local account" (see Note below)

All Systems:
- Guests group

Note: These are built-in security groups. "Local account" is more restrictive but may cause issues on servers such as systems that provide failover clustering.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57920r849119_chk'
  tag severity: 'medium'
  tag gid: 'V-254435'
  tag rid: 'SV-254435r849121_rule'
  tag stig_id: 'WN22-MS-000080'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-57871r849120_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
