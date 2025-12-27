control 'SV-47118' do
  title 'The Deny logon as a service user right on workstations must be configured to prevent access from highly privileged domain accounts on domain systems.  No other groups or accounts must be assigned this right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny logon as a service" right defines accounts that are denied log on as a service.  

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Incorrect configurations could prevent services from starting and result in a DoS.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on as a service" to include the following for domain joined systems.

Enterprise Admins Group
Domain Admins Group

Configure the "Deny logon as a service" for non-domain systems to include no entries (blank).'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-26484'
  tag rid: 'SV-47118r1_rule'
  tag stig_id: 'WINUR-000019'
  tag gtitle: 'Deny log on as a service'
  tag fix_id: 'F-41006r5_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
end
