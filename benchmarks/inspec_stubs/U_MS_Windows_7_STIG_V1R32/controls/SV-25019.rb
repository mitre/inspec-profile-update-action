control 'SV-25019' do
  title 'The Deny access to this computer from the network user right on workstations must be configured to prevent access from highly privileged domain accounts and all local accounts on domain systems and unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny access to this computer from the network" right defines the accounts that are prevented from logging on from the network.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Local accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny access to this computer from the network" right, this is a finding.

Domain Systems Only:
Enterprise Admins group
Domain Admins group
Local account (see Note below)

All Systems:
Guests group

Systems dedicated to the management of Active Directory (AD admin platforms, see V-36436 in the Active Directory Domain STIG) are exempt from denying the Enterprise Admins and Domain Admins groups.

Note: Microsoft Security Advisory Patch 2871997 adds new built-in security groups, including "Local account", to Windows 7 for assigning permissions and rights to all local accounts.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Deny access to this computer from the network" to include the following.

Domain Systems Only:
Enterprise Admins group
Domain Admins group
Local account (see Note below)

All Systems:
Guests group

Systems dedicated to the management of Active Directory (AD admin platforms, see V-36436 in the Active Directory Domain STIG) are exempt from denying the Enterprise Admins and Domain Admins groups.

Note: Microsoft Security Advisory Patch 2871997 adds new built-in security groups, including "Local account", to Windows 7 for assigning permissions and rights to all local accounts.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-69249r3_chk'
  tag severity: 'medium'
  tag gid: 'V-1155'
  tag rid: 'SV-25019r5_rule'
  tag stig_id: 'WINUR-000017'
  tag gtitle: 'Deny Access from the Network'
  tag fix_id: 'F-74857r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
