control 'SV-223268' do
  title 'The SharePoint farm service account (database access account) must be configured with minimum privileges on the SQL server.'
  desc 'Separation of duties is a prevalent Information Technology control implemented at different layers of the information system including the operating system and in applications. It serves to eliminate or reduce the possibility that a single user may carry out a prohibited action. Separation of duties requires the person accountable for approving an action not be the same person who is tasked with implementing the action. 

This requirement is intended to limit exposure due to user accounts being used to operate from within a privileged account or role. Limiting the access and permissions of privileged accounts to the minimum required, reduces exposure if the account is compromised and provides forensic history of activity when operating from these accounts. 
This policy limits the Farm Account privileges in AD.  However, default permissions for this account are configured by the SharePoint Products Configuration Wizard during product installation. This account is referred to during the installation as the "Database Access" account. By default, the account is used as the service account for the SharePoint Timer Service and the SharePoint Central Administration Web Site Application Pool. These settings should not be changed. Furthermore, this account should not be used as the service account for non-privileged services, applications, or application pools.'
  desc 'check', 'Review the SharePoint server configuration to ensure the farm service account (database access account) is configured with minimum privileges on the SQL server.

- Launch the SQL Server Management Console and navigate to Security >> Logins. 
- Select the SharePoint farm service account. 
- Click on "Server Roles" and verify only public, dbcreator, and securityadmin are checked.
- Click on "User Mapping" and verify that the farm account is a member of the public and db_owner role on each SharePoint database.

Otherwise, this is a finding.'
  desc 'fix', 'Configure the SharePoint farm service account (database access account) with minimum privileges on the SQL server.

Configure the account on each SQL server in the farm.
- Launch the SQL Server Management Console and navigate to Security >> Logins. 
- Select the SharePoint farm service account.
- Click on Server Roles.
- Ensure only public, dbcreator, and securityadmin roles are checked.
- Remove checks from all other roles.'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint Server 2013'
  tag check_id: 'C-24941r430861_chk'
  tag severity: 'medium'
  tag gid: 'V-223268'
  tag rid: 'SV-223268r612235_rule'
  tag stig_id: 'SP13-00-000165'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24929r430862_fix'
  tag 'documentable'
  tag legacy: ['V-59999', 'SV-74429']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
