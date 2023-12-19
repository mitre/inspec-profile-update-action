control 'SV-225646' do
  title 'The Samsung SDS EMM must be configured to have at least one user in the following Administrator roles: Server primary administrator, security configuration administrator, device user group administrator, auditor.'
  desc 'Having several administrative roles for the Samsung SDS EMM supports separation of duties. This allows administrator-level privileges to be granted granularly, such as giving application management privileges to one group and security policy privileges to another group. This helps prevent administrators from intentionally or inadvertently altering other settings and configurations they may not understand or approve of, which can weaken overall security and increase the risk of compromise.

- Server primary administrator: Responsible for server installation, initial configuration, and maintenance functions. Responsible for the setup and maintenance of security configuration administrator and auditor accounts. Responsible for the maintenance of applications in the MAS.
- Security configuration administrator: Responsible for security configuration of the server, defining device user groups, setup and maintenance of device user group administrator accounts, and defining privileges of device user group administrators.
- Device user group administrator: Responsible for maintenance of mobile device accounts, including setup, change of account configurations, and account deletion. Responsible for defining which apps user groups or individual users have access to in the MAS. Can only perform administrative functions assigned by the security configuration administrator.
- Auditor: Responsible for reviewing and maintaining server and mobile device audit logs.

SFR ID: FMT_SMR.1.1(1)'
  desc 'check', 'Review the Samsung SDS EMM configuration settings and verify the server is configured with the following Administrator roles: 
- Server primary administrator
- Security configuration administrator
- Device user group administrator
- Auditor

This validation procedure is performed on the MDM Administration Console.

On the MDM console, do the following to verify that users in the roles (b), (c), and (d) exist:
1. Log in to the Samsung SDS EMM Server Admin Console using a web browser.
2. Go to Settings >> Admin Console >> Administrators.
3. Observe that the user with the Security configuration administrator role is in the list on this screen, that the "Type" column indicates "Super", and that a modify symbol appears under all of the columns for "App", "Cert", "Org", "Profile", "Portal", and "Audit".
4. Observe that the user with the Device user group administrator role is in the list on this screen, that the "Type" column indicates "Common", and that a modify symbol appears under all of the columns for "App", "Cert", "Org", "Profile", "Portal", and "Audit".
5. Observe that the user with the Auditor role is in the list on this screen, that the "Type" column indicates "Common", and that a modify symbol appears only under the "Audit" column.

No verification is needed for the Server primary administrator since this role is always created automatically during server install.

If the MDM console is not configured with the required Administrator roles, this is a finding.'
  desc 'fix', 'Configure the Samsung SDS EMM with the following Administrator roles: 
- Server primary administrator
- Security configuration administrator
- Device user group administrator
- Auditor

On the MDM console, do the following to create users in the roles (b), (c) and (d):
1. Log in to the Samsung SDS EMM Server Admin Console using a web browser.
2. Go to Settings >> Admin Console >> Administrators and click on the "+" button near the top of the screen.
3. In the "Add Administrator" window, fill in the following once for each user account being created:
a. Choose the "New" radio button.
b. Fill in the "Admin ID" and "Admin Name" fields with a value for a new user.
c. To create a Security configuration administrator, do the following: Set the Type field to "Super".
d. To create a Device user group administrator, do the following: Set the Type field to "Common" and check all of the "Authorization" boxes.  
e. To create an Auditor, do the following: Set the Type field to "common" and check only the Audit box.  
4. Choose "Save" to create the account with the specified role.
5. Click "Yes" in next dialog box (Save box) to complete setup of user.

A user in the Server Primary Administrator role is created by defining a Windows Administrator account on the platform running the Samsung SDS EMM server. This is automatically created during server install.'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27347r560962_chk'
  tag severity: 'medium'
  tag gid: 'V-225646'
  tag rid: 'SV-225646r588007_rule'
  tag stig_id: 'SSDS-00-000570'
  tag gtitle: 'PP-MDM-411058'
  tag fix_id: 'F-27335r560963_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002226', 'CCI-002227']
  tag nist: ['CM-6 b', 'AC-6 (5)', 'AC-6 (5)']
end
