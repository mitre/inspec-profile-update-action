control 'SV-87855' do
  title 'The Samsung SDS EMM server must be configured with the Administrator roles: a. MD user; b. Server primary administrator; c. Security configuration administrator; d. Device user group administrator; and e. Auditor.'
  desc 'Having several roles for the Samsung SDS EMM server supports separation of duties. This allows administrator-level privileges to be granted granularly, such as giving application management privileges to one group and security policy privileges to another group. This helps prevent administrators from intentionally or inadvertently altering other settings and configurations they may not understand or approve of, which can weaken overall security and increase the risk of compromise.

- Server primary administrator: responsible for server installation, initial configuration, and maintenance functions. Responsible for the setup and maintenance of Security configuration administrator and Auditor accounts.
- Security configuration administrator: responsible for security configuration of the server, setting up and maintenance of mobile device security policies, defining device user groups, setup and maintenance of device user group administrator accounts, and defining privileges of device user group administrators.
- Device user group administrator: responsible for maintenance of mobile device accounts, including setup, change of account configurations, and account deletion. Can only perform administrative functions assigned by the Security configuration administrator.
- Auditor: responsible for reviewing and maintaining server and mobile device audit logs.

SFR ID: FMT_SMR.1.1(1) Refinement'
  desc 'check', 'Review the MDM server configuration settings and verify the server is configured with the Administrator roles: 
a. MD user;
b. Server primary administrator;
c. Security configuration administrator;
d. Device user group administrator; and 
e. Auditor. 

This validation procedure is performed on the MDM Administration Console.

On the MDM console, do the following to verify that users in the roles MD user exists:
1) Log in to the Samsung SDS EMM Server Admin Console using a web browser.
2) Go to Devices & Users >> Users & Organization. 
3) Observe that the user created in the Implementation Guidance is listed on this screen.

On the MDM console, do the following to verify that users in the roles (c), (d) and (e) exist:
1) Log in to the Samsung SDS EMM Server Admin Console using a web browser.
2) Go to Settings >> Admin Console >> Administrators.
3) Observe that the user with the Security configuration administrator role is in the list on this screen, that the “Type” column indicates “Super”, and that a modify symbol appears under all of the columns for “App”, “Cert”, “Org”, “Profile”, “Portal”, and “Audit”.
4) Observe that the user with the Device user group administrator role is in the list on this screen, that the “Type” column indicates “Common”, and that a modify symbol appears under all of the columns for “App”, “Cert”, “Org”, “Profile”, “Portal”, and “Audit”.
5) Observe that the user with the Auditor role is in the list on this screen, that the “Type” column indicates “Common”, and that a modify symbol appears only under the “Audit” column.

No verification is needed for the Server primary administrator since this role is always automatically created during server install.

If the MDM console is not configured with required Administrator roles, this is a finding.'
  desc 'fix', 'Configure the MDM server with the Administrator roles: 
a. MD user; 
b. Server primary administrator;
c. Security configuration administrator;
d. Device user group administrator; and
e. Auditor.

On the MDM console, do the following to create an MD user:
1) Log in to the Samsung SDS EMM Server Admin Console using a web browser.
2) Go to Devices & Users >> Users & Organization and select the “+” to get a pull-down menu. Select “Add Single User”.
3) Complete fields with user specific information.
4) Click "Save".
5) Click "No" in next dialog box (OK box) to complete setup of user.

On the MDM console, do the following to create users in the roles (c), (d), and (e):
1) Log in to the Samsung SDS EMM Server Admin Console using a web browser.
2) Go to Settings >> Admin Console >> Administrators and click on the “+” button near the top of the screen.
3) In the “Add Administrator” window, fill in the following once for each user account being created:
a) Choose the “New” radio button.
b) Fill in the “Admin ID” and “Admin Name” fields with values for a new user.
c) To Create a Security configuration administrator do the following: Set the Type field to “Super”. 
d) To Create a Device user group administrator do the following: Set the Type field to “Common” and check all of the “Authorization” boxes. 
e) To Create an Auditor do the following: Set the Type field to “common” and check only the Audit box. 
4) Choose “Save” to create the account with the specified role.
5) Click "Yes" in next dialog box (Save box) to complete setup of user.

A user in the Server Primary Administrator role is created by defining a Windows Administrator account on the platform running the Samsung SDS EMM server. This is automatically created during server install.'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM 1.5.x'
  tag check_id: 'C-73305r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73203'
  tag rid: 'SV-87855r1_rule'
  tag stig_id: 'SEMM-15-000070'
  tag gtitle: 'PP-MDM-201104'
  tag fix_id: 'F-79649r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000128', 'CCI-000129', 'CCI-000169', 'CCI-000366', 'CCI-001571']
  tag nist: ['AU-2 (4)', 'AU-2 a', 'AU-12 a', 'CM-6 b', 'AU-2 a']
end
