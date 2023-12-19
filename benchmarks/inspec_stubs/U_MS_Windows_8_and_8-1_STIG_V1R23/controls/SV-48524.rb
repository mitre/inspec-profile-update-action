control 'SV-48524' do
  title 'The Deny log on through Remote Desktop Services user right on workstations must at a minimum be configured to prevent access from highly privileged domain accounts and local accounts on domain systems and unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny log on through Remote Desktop Services" right defines the accounts that are prevented from logging on using Remote Desktop Services.

If Remote Desktop Services is not used by the organization, the Everyone group must be assigned this right to prevent all access.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Local accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on through Remote Desktop Services" right, this is a finding:

If Remote Desktop Services is not used by the organization, the Everyone group can replace all of the groups listed below.

Domain Systems Only:
Enterprise Admin group
Domain Admin group
Local account (see Note below)

All Systems:
Guests group

Systems dedicated to the management of Active Directory (AD admin platforms, see V-36436 in the Active Directory Domain STIG) are exempt from denying the Enterprise Admins and Domain Admins groups.

Note: "Local account" is a built-in security group used to assign user rights and permissions to all local accounts.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on through Remote Desktop" to include the following.

If Remote Desktop Services is not used by the organization, assign the Everyone group this right to prevent all access.

Domain Systems Only:
Enterprise Admins group
Domain Admins group
Local account (see Note below)

All Systems:
Guests group

Systems dedicated to the management of Active Directory (AD admin platforms, see V-36436 in the Active Directory Domain STIG) are exempt from denying the Enterprise Admins and Domain Admins groups.

Note: "Local account" is a built-in security group used to assign user rights and permissions to all local accounts.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-66299r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26486'
  tag rid: 'SV-48524r4_rule'
  tag stig_id: 'WN08-UR-000021'
  tag gtitle: 'Deny log on through Remote Desktop \\ Terminal Services'
  tag fix_id: 'F-71687r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
