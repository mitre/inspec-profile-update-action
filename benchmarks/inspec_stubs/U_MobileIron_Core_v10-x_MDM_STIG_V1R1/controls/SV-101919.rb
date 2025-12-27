control 'SV-101919' do
  title 'The MobileIron Core v10 server must be configured to have at least one user in the following Administrator roles: Server primary administrator, security configuration administrator, device user group administrator, auditor.'
  desc 'Having several administrative roles for the MobileIron Core v10 server supports separation of duties. This allows administrator-level privileges to be granted granularly, such as giving application management privileges to one group and security policy privileges to another group. This helps prevent administrators from intentionally or inadvertently altering other settings and configurations they may not understand or approve of, which can weaken overall security and increase the risk of compromise.

- Server primary administrator: Responsible for server installation, initial configuration, and maintenance functions. Responsible for the setup and maintenance of security configuration administrator and auditor accounts. Responsible for the maintenance of applications in the MAS.
- Security configuration administrator: Responsible for security configuration of the server, defining device user groups, setup and maintenance of device user group administrator accounts, and defining privileges of device user group administrators.
- Device user group administrator: Responsible for maintenance of mobile device accounts, including setup, change of account configurations, and account deletion. Responsible for defining which apps user groups or individual users have access to in the MAS. Can only perform administrative functions assigned by the security configuration administrator.
- Auditor: Responsible for reviewing and maintaining server and mobile device audit logs.

SFR ID: FMT_SMR.1.1(1)'
  desc 'check', 'Review the MDM server configuration settings and verify the server is configured with the Administrator roles: 
- Server primary administrator
- Security configuration administrator
- Device user group administrator
- Auditor

On the MDM console, do the following:
1. Verify a user is in the "Server primary administrator" role.
a. Logon to the MobileIron Core Server system manager portal as a user with the "server primary administrator" role using a web browser.
b. Select Security >> Identity Source >> Local Users.

If a user in the "server primary administrator" role is not listed, this is a finding.

2. Verify a user is in the "Security configuration administrator" role.
a. Logon to the MobileIron Core Server administrator portal as a user with the "server primary administrator" role using a web browser.
b. Select Admin >> Admins.
c. Select user with the "Security configuration administrator" role.
d. Click Actions >> Edit Roles.
e. Verify that the following roles are selected: "Manage label", "View user", "Manage app", "Manage configuration", "Manage policy", "Manage settings and services", and "Manage administrators and device" spaces.

If the "Security configuration administrator" user is not found or any of the required roles are not selected, this is a finding.

3. Verify a user is in the "Device user group administrator" role.
a. Logon to the MobileIron Core Server administrator portal as a user with the "server primary administrator" role using a web browser.
b. Select Admin >> Admins.
c. Select user with the "Device user group administrator" role.
d. Click Actions >> Edit Roles.
e. Verify that the following roles are selected: "wipe devices", "add device", "manage ActiveSync device", and "delegate retired device" roles.

If the "Device user group administrator" user is not found or any of the required roles are not selected, this is a finding.

4. Verify a user is in the "Auditor" role. 
a. Logon to the MobileIron Core Server administrator portal as a user with the "server primary administrator" role using a web browser.
b. Select Admin >> Admins.
c. Select user with the "Device user group administrator" role.
d. Click Actions >> Edit Roles.
e. Check that the following roles are selected: "Manage logs and events".

If the user is not found or any of the required roles are not selected, this is a finding.'
  desc 'fix', 'Configure the MDM server with the Administrator roles: 
- Server primary administrator
- Security configuration administrator
- Device user group administrator
- Auditor 

On the MDM console, do the following:
1. Follow the instructions in the "MobileIron Core and Android Client Mobile Device Management Protection Profile Guide" in section "Configuring administrators to have roles defined by federal requirements":
a. Follow the instructions for "Configuring administrators to be a server primary administrator".
b. Follow the instructions for "Configuring administrators to be a security configuration administrator".
c. Follow the instructions for "Configuring administrators to be a device user group administrator".
d. Follow the instructions for "Configuring administrators to be an auditor".
2. In each case instructions are provided to create a new user with the identified role.'
  impact 0.5
  ref 'DPMS Target MobileIron Core 10.x MDM'
  tag check_id: 'C-90975r1_chk'
  tag severity: 'medium'
  tag gid: 'V-91817'
  tag rid: 'SV-101919r1_rule'
  tag stig_id: 'MICR-10-000590'
  tag gtitle: 'PP-MDM-311058'
  tag fix_id: 'F-98019r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002226', 'CCI-002227']
  tag nist: ['CM-6 b', 'AC-6 (5)', 'AC-6 (5)']
end
