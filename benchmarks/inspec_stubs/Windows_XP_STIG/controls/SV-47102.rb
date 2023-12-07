control 'SV-47102' do
  title 'The Deny logon locally user right on workstations must be configured to prevent access from highly privileged domain accounts on domain systems and unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny logon locally" right defines accounts that are prevented from logging on interactively.  

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

The Guests group and Support_388945a0 account must be assigned this right to prevent unauthenticated access.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on locally" to include the following.

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group

Workstations dedicated to the management of Active Directory (see V-36436 in the Active Directory Domain STIG) are exempt from this.

All Systems:
Guests Group'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-26485'
  tag rid: 'SV-47102r2_rule'
  tag stig_id: 'WINUR-000020'
  tag gtitle: 'Deny log on locally'
  tag fix_id: 'F-43261r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
end
