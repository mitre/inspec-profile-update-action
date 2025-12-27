control 'SV-47135' do
  title 'The Deny logon through Terminal Services user right on workstations must prevent all access if TS is not used by the organization.  If TS is used, it must be configured to prevent access from highly privileged domain accounts and local administrator accounts on domain systems and unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny logon through Terminial Services" right defines the accounts that are prevented from logging on using Terminal Services.

If Terminal Services is not used by the organization, the Everyone group must be assigned this right to prevent all access.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Local administrator accounts on domain joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny logon through Terminal Services" right, this is a finding.

If Terminal Services is not used by the organization, the Everyone group can replace all of the groups listed below.

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group
*All Local Administrator Accounts

All Systems:
Guests Group

*Note: Do not include the built-in Administrators group.  This group must contain the appropriate accounts/groups responsible for administering the system.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny logon through Terminal Services" to include the following.

If Terminal Services is not used by the organization, assign the Everyone group this right to prevent all access.

If TS is used by the organization, assign the following groups.

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group
*All Local Administrator Accounts

All Systems:
Guests Group

*Note: Do not include the built-in Administrators group.  This group must contain the appropriate accounts/groups responsible for administering the system.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-44712r6_chk'
  tag severity: 'medium'
  tag gid: 'V-26486'
  tag rid: 'SV-47135r1_rule'
  tag stig_id: 'WINUR-000021'
  tag gtitle: 'Deny log on through Remote Desktop \\ Terminal Services'
  tag fix_id: 'F-41012r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
end
