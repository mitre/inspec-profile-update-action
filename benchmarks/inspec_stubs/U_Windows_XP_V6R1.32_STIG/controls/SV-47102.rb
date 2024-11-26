control 'SV-47102' do
  title 'The Deny logon locally user right on workstations must be configured to prevent access from highly privileged domain accounts on domain systems and unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny logon locally" right defines accounts that are prevented from logging on interactively.  

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

The Guests group and Support_388945a0 account must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on locally" right, this is a finding.

Domain Systems Only:
Enterprise Admins group
Domain Admins group

All Systems:
Guests group
Support_388945a0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on locally" to include the following.

Domain Systems Only:
Enterprise Admins group
Domain Admins group

All Systems:
Guests group   
Support_388945a0'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-49421r3_chk'
  tag severity: 'medium'
  tag gid: 'V-26485'
  tag rid: 'SV-47102r3_rule'
  tag stig_id: 'WINUR-000020'
  tag gtitle: 'Deny log on locally'
  tag fix_id: 'F-49509r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
end
