control 'SV-47142' do
  title 'The Deny log on through Terminal Services user right on member servers must be configured to prevent access from highly privileged domain accounts and local administrator accounts on domain systems and unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny log on through Terminal Services" right defines the accounts that are prevented from logging on using Terminal Services.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Local administrator accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on through Terminal Services" right, this is a finding:

Domain Systems Only:
Enterprise Admins group
Domain Admins group
*All Local Administrator Accounts using the "DenyNetworkAccess" or "DeniedNetworkAccess" group (see V-45589).  Do not use the built-in Administrators group.  This group must contain the appropriate accounts/groups responsible for administering the system.

All Systems:
Guests group

*Documentation and scripts supporting the use of this group to restrict local administrative accounts were changed at one point.  The original name, "DeniedNetworkAccess", was changed to "DenyNetworkAccess".  Automated benchmarks will look for either of these groups.  Use of other methods will require manual validation.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on through Terminal Services" to include the following.

Domain Systems Only:
Enterprise Admins group
Domain Admins group
*All Local Administrator Accounts using the "DenyNetworkAccess" or "DeniedNetworkAccess" group (see V-45589).  Do not use the built-in Administrators group.  This group must contain the appropriate accounts/groups responsible for administering the system.

All Systems:
Guests group

*Documentation and scripts supporting the use of this group to restrict local administrative accounts were changed at one point.  The original name, "DeniedNetworkAccess", was changed to "DenyNetworkAccess".  Automated benchmarks will look for either of these groups.  Use of other methods will require manual validation.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-58051r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26486'
  tag rid: 'SV-47142r3_rule'
  tag stig_id: 'WINUR-000021-MS'
  tag gtitle: 'Deny log on through Remote Desktop \\ Terminal Services'
  tag fix_id: 'F-62413r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
