control 'SV-29596' do
  title 'The Deny access to this computer from the network user right on workstations must be configured to prevent access from highly privileged domain accounts and local administrator accounts on domain systems and unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny Access from the Network" right defines the accounts that are prevented from logging on from the network.  

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Local administrator accounts on domain joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.

The Guests group and Support_388945a0 account must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny access to this computer from the network" right, this is a finding.

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group
*All Local Administrator Accounts

All Systems:
Guests Group
Support_388945a0

*NOTE:  Do not include the built-in Administrators group.  This group must contain the appropriate accounts/groups responsible for administering the system.

Note: If an account listed has been deleted from the system such as the Support_388945a0 account, automated review tools may incorrectly report the account as a finding. If the account does not exist on a system it would not be a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny access to this computer from the network" to include the following.

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group
*All Local Administrator Accounts

All Systems:
Guests Group
Support_388945a0

*Note: Do not include the built-in Administrators group.  This group must contain the appropriate accounts/groups responsible for administering the system.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-44700r4_chk'
  tag severity: 'medium'
  tag gid: 'V-1155'
  tag rid: 'SV-29596r2_rule'
  tag stig_id: 'WINUR-000017'
  tag gtitle: 'Deny Access from the Network'
  tag fix_id: 'F-41000r3_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECLP-1'
end
