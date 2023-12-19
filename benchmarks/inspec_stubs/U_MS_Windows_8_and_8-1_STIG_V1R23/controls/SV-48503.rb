control 'SV-48503' do
  title 'The Deny log on as a service user right on workstations must be configured to prevent access from highly privileged domain accounts on domain systems and unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny log on as a service" right defines accounts that are denied log on as a service.  

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Incorrect configurations could prevent services from starting and result in a DoS.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on as a service" right on domain joined systems, this is a finding:

Enterprise Admin Group
Domain Admin Group

If any accounts or groups are defined for the "Deny log on as a service" right on non-domain joined systems, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on as a service" to include the following for domain joined systems.

Enterprise Admin Group
Domain Admin Group

Configure the "Deny log on as a service" for non-domain systems to include no entries (blank).'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45153r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26484'
  tag rid: 'SV-48503r1_rule'
  tag stig_id: 'WN08-UR-000019'
  tag gtitle: 'Deny log on as service'
  tag fix_id: 'F-41626r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
