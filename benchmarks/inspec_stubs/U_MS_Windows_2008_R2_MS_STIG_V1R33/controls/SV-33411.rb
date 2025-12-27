control 'SV-33411' do
  title 'The Deny log on through Remote Desktop Services user right on member servers must be configured to prevent access from highly privileged domain accounts and all local accounts on domain systems and unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny log on through Remote Desktop Services" right defines the accounts that are prevented from logging on using Remote Desktop Services.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Local accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.

Expand the Security Configuration and Analysis tree view.

Navigate to Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on through Remote Desktop/Terminal Services" right, this is a finding.

Domain Systems Only:
Enterprise Admins group
Domain Admins group
Local account (see Note below)

All Systems:
Guests group

Note: Microsoft Security Advisory Patch 2871997 adds new built-in security groups, including "Local account", to Windows Server 2008 R2 for assigning permissions and rights to all local accounts.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Deny log on through Remote Desktop/Terminal Services" to include the following.

Domain Systems Only:
Enterprise Admins group
Domain Admins group
Local account (see Note below)

All Systems:
Guests group

Note: Microsoft Security Advisory Patch 2871997 adds new built-in security groups, including "Local account", to Windows Server 2008 R2 for assigning permissions and rights to all local accounts.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-81121r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26486'
  tag rid: 'SV-33411r6_rule'
  tag stig_id: 'WINUR-000021-MS'
  tag gtitle: 'Deny log on through Remote Desktop \\ Terminal Services'
  tag fix_id: 'F-88197r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
