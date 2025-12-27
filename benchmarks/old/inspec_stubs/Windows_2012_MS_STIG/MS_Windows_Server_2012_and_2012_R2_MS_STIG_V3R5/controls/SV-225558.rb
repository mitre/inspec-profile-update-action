control 'SV-225558' do
  title 'The Deny log on as a batch job user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems, and from unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on as a batch job" user right defines accounts that are prevented from logging on to the system as a batch job such, as Task Scheduler.  

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

The Guests group must be assigned to prevent unauthenticated access.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on as a batch job" user right, this is a finding:

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group

All Systems:
Guests Group'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on as a batch job" to include the following:

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group

All Systems:
Guests Group'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27257r472016_chk'
  tag severity: 'medium'
  tag gid: 'V-225558'
  tag rid: 'SV-225558r569185_rule'
  tag stig_id: 'WN12-UR-000018-MS'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-27245r472017_fix'
  tag 'documentable'
  tag legacy: ['V-26483', 'SV-51502']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
