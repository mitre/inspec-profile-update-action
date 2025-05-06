control 'SV-223271' do
  title 'The SharePoint setup account must be configured with the minimum privileges for the local server.'
  desc 'Separation of duties is a prevalent Information Technology control implemented at different layers of the information system including the operating system and in applications. It serves to eliminate or reduce the possibility that a single user may carry out a prohibited action. Separation of duties requires the person accountable for approving an action not be the same person who is tasked with implementing the action. 

This requirement is intended to limit exposure due to user accounts being used to operate from within a privileged account or role. Limiting the access and permissions of privileged accounts to the minimum required, reduces exposure if the account is compromised and provides forensic history of activity when operating from these accounts.

This policy limits the setup account privileges in AD.  However, default permissions for this account are configured by the SharePoint Products Configuration Wizard during product installation. This account is referred to during the installation as the "Database Access" account. By default, the account is used as the service account for the SharePoint Timer Service and the SharePoint Central Administration Web Site Application Pool. These settings should not be changed. Furthermore, this account should not be used as the service account for non-privileged services, applications, or application pools.'
  desc 'check', 'Review the SharePoint server configuration to ensure the setup account is configured with the minimum privileges for the local server.

- On the server(s) where the SharePoint software is installed, navigate to Server Manager >> Local Users and Groups.
- Select the “Member of” tab and verify this account is only a member of the Administrators, WSS_ADMIN_WPG, and IIS_IUSRS groups.
- Select the other tabs in this area to verify no other services or permissions are configured for this account.

If the Setup User account is a member of any other groups than Administrators, WSS_ADMIN_WPG, and IIS_IUSRS on the local server where SharePoint is installed, this is a finding.'
  desc 'fix', 'Configure the SharePoint setup account with the minimum privileges for the local server.

- On the server(s) where the SharePoint software is installed, navigate to Server Manager -> Local Users and Groups.
- Select the “Member of” tab. 
- Configure the SharePoint Setup User as a member of Administrators, WSS_ADMIN_WPG, and IIS_IUSRS groups.
- Remove all other group memberships from this account. 
- Select the other tabs in this area and remove other services or permissions configured for this account.'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint Server 2013'
  tag check_id: 'C-24944r430870_chk'
  tag severity: 'medium'
  tag gid: 'V-223271'
  tag rid: 'SV-223271r612235_rule'
  tag stig_id: 'SP13-00-000180'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24932r430871_fix'
  tag 'documentable'
  tag legacy: ['V-60005', 'SV-74435']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
