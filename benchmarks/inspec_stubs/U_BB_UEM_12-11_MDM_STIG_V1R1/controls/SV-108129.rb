control 'SV-108129' do
  title 'The BlackBerry UEM 12.11 server must be configured to have at least one user in the following Administrator roles: Server primary administrator, security configuration administrator, device user group administrator, auditor.'
  desc 'Having several administrative roles for the BlackBerry UEM 12.11 server supports separation of duties. This allows administrator-level privileges to be granted granularly, such as giving application management privileges to one group and security policy privileges to another group. This helps prevent administrators from intentionally or inadvertently altering other settings and configurations they may not understand or approve of, which can weaken overall security and increase the risk of compromise.

- Server primary administrator: Responsible for server installation, initial configuration, and maintenance functions. Responsible for the setup and maintenance of security configuration administrator and auditor accounts. Responsible for the maintenance of applications in the MAS.
- Security configuration administrator: Responsible for security configuration of the server, defining device user groups, setup and maintenance of device user group administrator accounts, and defining privileges of device user group administrators.
- Device user group administrator: Responsible for maintenance of mobile device accounts, including setup, change of account configurations, and account deletion. Responsible for defining which apps user groups or individual users have access to in the MAS. Can only perform administrative functions assigned by the security configuration administrator.
- Auditor: Responsible for reviewing and maintaining server and mobile device audit logs.

SFR ID: FMT_SMR.1.1(1)'
  desc 'check', 'Review the BlackBerry UEM 12.11 server configuration settings.

Verify the server is configured with the "Administrator" roles: 
a. UEM Security Administrator;
b. Auditor;
c. One or more Site Custom Administrator or UEM predefined enterprise/help desk roles.

Note: The exact name of the role is not important. Each role should include functions close to the role descriptions listed in the VulDiscussion.

Note: The intent of the requirement is that separate people perform each administrator role; few users are assigned to the "UEM Security Administrator" role; the "auditor" role is limited to only authorized permissions; and day-to-day management of user accounts, group accounts, and profiles are performed from site-specific custom administrator roles or UEM predefined enterprise/help desk roles instead of the "UEM Security Administrator".

On the BlackBerry UEM 12.11, do the following:
1. Log in to the BlackBerry UEM 12.11 console.
2. Select the "Settings" tab at the top of the screen.
3. Expand the "General" settings tab on the left pane.
4. Expand the "Administrators" tab on the left pane.
5. Select the "Roles" tab on the left pane.
6. Verify at least one user is assigned to each of the following roles:
a. UEM Security Administrator;
b. Auditor;
c. One or more Site Custom Administrator or UEM predefined enterprise/help desk roles.

Verify the auditor role function is limited to only reviewing and maintaining server and mobile device audit logs as follows:
1. Log in to the BlackBerry UEM 12.11 console. Select the "Settings" tab at the top of the screen.
2. Expand the "Administrators" tab on the left pane.
3. Select the "Roles" tab on the left pane.
4. Click the "Auditor" role.
5. Verify the role only has the following permissions assigned:
- View audit information;
- View audit settings;
- Edit audit settings and purge data; and
- Edit logging settings.

Talk to the "UEM Security Administrator".

Verify custom administrator roles/UEM predefined enterprise/help desk roles are used for day-to-day management of user accounts, group accounts, and profiles.

If at least one user is not associated with the "UEM Security Administrator", "Auditor", and one or more site custom administrator roles/UEM predefined enterprise/help desk roles, this is a finding.

If the "auditor" role has more permissions than authorized, this is a finding.

If day-to-day management of user accounts, group accounts, and profiles is primarily performed by "UEM Security Administrators" instead of one or more site custom administrator roles/UEM predefined enterprise/help desk roles, this is a finding.'
  desc 'fix', 'On the BlackBerry UEM 12.11, do the following:

Using the procedures below:
- Assign at least one user to the UEM Security Administrator role. Few administrators should be assigned to this role. 
Note: UEM automatically restricts the following functions to only the Security Administrator: Full permissions to manage the BlackBerry Enterprise Solution. Create and edit roles.
- Define an "Auditor" role (see the VulDiscussion for role functions). Assign at least one user (UEM administrator) to the role. The role should include only the following UEM permissions:
** View audit information;
** Delete BlackBerry Dynamics audit log files;
** View and export BlackBerry Dynamics audit log files;
** View audit settings;
** Edit audit settings and purge data;
** Edit logging settings.
- Define site custom administrator roles or UEM predefined enterprise/help desk roles as needed to administer device policies and user accounts (for example, see the Security Configuration Administrator and Device User Group Administrator in the VulDiscussion). Assign users to the roles as required. These roles should be used for day-to-day management of user accounts, group accounts, and profiles.

To set up specific roles, do the following:
1. Go to Settings >> Administrators >> Roles.
2. Select "roles" in the left pane.
3. Select "add a role" on the top right.
4. Assign appropriate name and functions to the role. 
5. Click "Save".

To assign users or groups to a role, do the following:
1. Log in to the BlackBerry UEM 12.11 console and select the "Settings" tab at the top of the screen.
2. Expand the "General" settings tab on the left pane.
3. Expand the "Administrators" tab on the left pane.

To assign a role to a user:
1. Click "Users".
2. Click the "Add an administrator icon" (upper right corner).
3. If necessary, search for a user account.
4. Click the name of the user account.
5. In the Role drop-down list, click the role to be added.
6. Click "Save".

To assign a role to a group:
1. Click "Groups".
2. Click the Add an administrator icon (upper right corner).
3. If necessary, search for a user group.
4. Click the name of the user group.
5. In the Role drop-down list, click the role that you want to add.
6. Click "Save".

Note: The intent of the requirement is that separate people perform each administrator role. The exact name of the role is not important.'
  impact 0.5
  ref 'DPMS Target BlackBerry Unified Endpoint Manager (UEM) 12.11'
  tag check_id: 'C-97865r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99025'
  tag rid: 'SV-108129r1_rule'
  tag stig_id: 'BUEM-12-110100'
  tag gtitle: 'PP-MDM-411058'
  tag fix_id: 'F-104701r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002226', 'CCI-002227']
  tag nist: ['CM-6 b', 'AC-6 (5)', 'AC-6 (5)']
end
