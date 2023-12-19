control 'SV-223267' do
  title 'The SharePoint farm service account (database access account)  must be configured with minimum privileges in Active Directory (AD).'
  desc 'Separation of duties is a prevalent Information Technology control implemented at different layers of the information system including the operating system and in applications. It serves to eliminate or reduce the possibility that a single user may carry out a prohibited action. Separation of duties requires the person accountable for approving an action not be the same person who is tasked with implementing the action. 

This requirement is intended to limit exposure due to user accounts being used to operate from within a privileged account or role. Limiting the access and permissions of privileged accounts to the minimum required, reduces exposure if the account is compromised and provides forensic history of activity when operating from these accounts. 
This policy limits the Farm Account privileges in AD.  However, default permissions for this account are configured by the SharePoint Products Configuration Wizard during product installation. This account is referred to during the installation as the "Database Access" account. By default, the account is used as the service account for the SharePoint Timer Service and the SharePoint Central Administration Web Site Application Pool. These settings should not be changed. Furthermore, this account should not be used as the service account for non-privileged services, applications, or application pools.'
  desc 'check', 'Review the SharePoint server configuration to ensure the farm service account (database access account)  is configured with minimum privileges in Active Directory (AD).

- Verify the account has least privilege in Active Directory.
- Navigate to “Active Directory Users and Computers” >> Users.
- Double click on the account to view the account properties.
- Select the “Members of” tab and verify this account is a member of the Domain Users group only.
- Select the other tabs in this area to verify no other services or permissions are configured for this account.

If the farm service account is a member of other groups other than Domain Users, this is a finding.

If the Setup User account has unneeded permissions or services assigned, this is a finding.'
  desc 'fix', 'Configure the SharePoint farm service account (database access account) with minimum privileges in Active Directory (AD).

Ensure the Setup User domain user has minimum permissions in Active Directory. 
- Using the AD DS console, navigate to “Active Directory Users and Computers” >> Users.
- Double click on the account to view the account properties.
- Select the “Members of” tab and configure the farm service account is a member of the Domain Users group. Remove any other group membership from the account.
- Select the other tabs in this area and remove any services or permissions configured for this account.'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint Server 2013'
  tag check_id: 'C-24940r430858_chk'
  tag severity: 'medium'
  tag gid: 'V-223267'
  tag rid: 'SV-223267r612235_rule'
  tag stig_id: 'SP13-00-000160'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24928r430859_fix'
  tag 'documentable'
  tag legacy: ['V-59997', 'SV-74427']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
