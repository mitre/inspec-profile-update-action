control 'SV-29598' do
  title 'The Deny access to this computer from the network user right on workstations must be configured to prevent access from highly privileged domain accounts and local administrator accounts on domain systems and unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny access to this computer from the network" right defines the accounts that are prevented from logging on from the network.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Local administrator accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny access to this computer from the network" to include the following.

Domain Systems Only:
Enterprise Admins group
Domain Admins group
*All Local Administrator Accounts using the "DenyNetworkAccess" or "DeniedNetworkAccess" group (see V-45589).  Do not use the built-in Administrators group.  This group must contain the appropriate accounts/groups responsible for administering the system.

All Systems:
Guests group

*Documentation and scripts supporting the use of this group to restrict local administrative accounts were changed at one point.  The original name, "DeniedNetworkAccess", was changed to "DenyNetworkAccess".  Automated benchmarks will look for either of these groups.  Use of other methods will require manual validation.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-1155'
  tag rid: 'SV-29598r4_rule'
  tag stig_id: 'WINUR-000017'
  tag gtitle: 'Deny Access from the Network'
  tag fix_id: 'F-62393r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
