control 'SV-47103' do
  title 'The Deny log on locally user right on workstations must be configured to prevent access from highly privileged domain accounts on domain systems and unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny log on locally" right defines accounts that are prevented from logging on interactively.  

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on locally" to include the following.

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group

All Systems:
Guests Group'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-26485'
  tag rid: 'SV-47103r3_rule'
  tag stig_id: 'WINUR-000020'
  tag gtitle: 'Deny log on locally'
  tag fix_id: 'F-49511r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
