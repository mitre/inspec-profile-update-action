control 'SV-225561' do
  title 'The Deny log on through Remote Desktop Services user right on member servers must be configured to prevent access from highly privileged domain accounts and all local accounts on domain systems, and from unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on through Remote Desktop Services" user right defines the accounts that are prevented from logging on using Remote Desktop Services.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Local accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on through Remote Desktop Services" user right, this is a finding:

Domain Systems Only:
Enterprise Admins group
Domain Admins group
Local account (see Note below)

All Systems:
Guests group

Note: Windows Server 2012 R2 added new built-in security groups, including "Local account", for assigning permissions and rights to all local accounts. 
Microsoft Security Advisory Patch 2871997 adds the new security groups to Windows Server 2012.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Deny log on through Remote Desktop Services" to include the following:

Domain Systems Only:
Enterprise Admins group
Domain Admins group
Local account (see Note below)

All Systems:
Guests group

Note: Windows Server 2012 R2 added new built-in security groups, including "Local account", for assigning permissions and rights to all local accounts. 
Microsoft Security Advisory Patch 2871997 adds the new security groups to Windows Server 2012.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27260r472025_chk'
  tag severity: 'medium'
  tag gid: 'V-225561'
  tag rid: 'SV-225561r569185_rule'
  tag stig_id: 'WN12-UR-000021-MS'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-27248r472026_fix'
  tag 'documentable'
  tag legacy: ['SV-51509', 'V-26486']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
