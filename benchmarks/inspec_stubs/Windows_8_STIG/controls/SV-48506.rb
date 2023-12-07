control 'SV-48506' do
  title 'The Deny log on locally user right on workstations must be configured to prevent access from highly privileged domain accounts on domain systems and unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny log on locally" right defines accounts that are prevented from logging on interactively.  

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on locally" right, this is a finding.

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group

Workstations dedicated to the management of Active Directory (see V-36436 in the Active Directory Domain STIG) are exempt from this.

All Systems:
Guests Group'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on locally" to include the following.

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group

Workstations dedicated to the management of Active Directory (see V-36436 in the Active Directory Domain STIG) are exempt from this.

All Systems:
Guests Group'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45873r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26485'
  tag rid: 'SV-48506r2_rule'
  tag stig_id: 'WN08-UR-000020'
  tag gtitle: 'Deny log on locally'
  tag fix_id: 'F-43264r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
