control 'SV-47110' do
  title 'The Deny log on as a batch job user right on workstations must be configured to prevent access from highly privileged domain accounts on domain systems and unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny log on as a batch job" right defines accounts that are prevented from logging on to the system as a batch job, such as Task Scheduler.  

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

The Guests group must be assigned to prevent unauthenticated access.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on as a batch job" to include the following.

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group

All Systems:
Guests Group'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-26483'
  tag rid: 'SV-47110r1_rule'
  tag stig_id: 'WINUR-000018'
  tag gtitle: 'Deny log on as a batch job'
  tag fix_id: 'F-41004r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
