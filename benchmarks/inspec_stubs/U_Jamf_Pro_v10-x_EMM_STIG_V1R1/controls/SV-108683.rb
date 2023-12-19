control 'SV-108683' do
  title 'The Jamf Pro EMM server must be configured to have at least one user in the following Administrator roles: Server primary administrator, security configuration administrator, device user group administrator, auditor.'
  desc 'Having several administrative roles for the Jamf Pro EMM server supports separation of duties. This allows administrator-level privileges to be granted granularly, such as giving application management privileges to one group and security policy privileges to another group. This helps prevent administrators from intentionally or inadvertently altering other settings and configurations they may not understand or approve of, which can weaken overall security and increase the risk of compromise.

- Server primary administrator: Responsible for server installation, initial configuration, and maintenance functions. Responsible for the setup and maintenance of security configuration administrator and auditor accounts. Responsible for the maintenance of applications in the MAS.
- Security configuration administrator: Responsible for security configuration of the server, defining device user groups, setup and maintenance of device user group administrator accounts, and defining privileges of device user group administrators.
- Device user group administrator: Responsible for maintenance of mobile device accounts, including setup, change of account configurations, and account deletion. Responsible for defining which apps user groups or individual users have access to in the MAS. Can only perform administrative functions assigned by the security configuration administrator.
- Auditor: Responsible for reviewing and maintaining server and mobile device audit logs.

SFR ID: FMT_SMR.1.1(1)'
  desc 'check', 'Administrator and Audit level permission groups are configured by default within Jamf Pro server. 

Verify the additional group permissions by:

1. Open Jamf Pro server.
2. Open "Settings".
3. Select "Jamf Pro User Accounts and Groups".
4. View the necessary information for each group has been created with appropriate privilege sets.

Jamf Pro EMM server will have the appropriate group level permissions available for applying to individual user accounts or AD groups.

If required administrator roles have not been set up on the server, this is a finding.'
  desc 'fix', 'Administrator and Audit level permission groups are configured by default within Jamf Pro server. 

Configure the additional group permissions by:

1. Open Jamf Pro server.
2. Open "Settings".
3. Select "Jamf Pro User Accounts and Groups".
4. Select "New".
5. Select "Create Standard Group", click "Next".
6. Fill out all the necessary information for creating the group including the privilege set.
7. Click "Save".
8. Repeat for each group of permissions that are needed.

Once completed, Jamf Pro EMM server will have the appropriate group level permissions available for applying to individual user accounts or AD groups.'
  impact 0.5
  ref 'DPMS Target JAMF v10.x EMM'
  tag check_id: 'C-98429r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99579'
  tag rid: 'SV-108683r1_rule'
  tag stig_id: 'JAMF-10-000610'
  tag gtitle: 'PP-MDM-411058'
  tag fix_id: 'F-105263r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002226', 'CCI-002227']
  tag nist: ['CM-6 b', 'AC-6 (5)', 'AC-6 (5)']
end
