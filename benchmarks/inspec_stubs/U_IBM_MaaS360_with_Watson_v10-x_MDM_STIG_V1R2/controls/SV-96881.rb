control 'SV-96881' do
  title 'The MaaS360 MDM server must be configured to have at least one user in the following Administrator roles: Server primary administrator, security configuration administrator, device user group administrator, auditor.'
  desc 'Having several administrative roles for the MaaS360 MDM server supports separation of duties. This allows administrator-level privileges to be granted granularly, such as giving application management privileges to one group and security policy privileges to another group. This helps prevent administrators from intentionally or inadvertently altering other settings and configurations they may not understand or approve of, which can weaken overall security and increase the risk of compromise.

- Server primary administrator: Responsible for server installation, initial configuration, and maintenance functions. Responsible for the setup and maintenance of security configuration administrator and auditor accounts. Responsible for the maintenance of applications in the MAS.
- Security configuration administrator: Responsible for security configuration of the server, defining device user groups, setup and maintenance of device user group administrator accounts, and defining privileges of device user group administrators.
- Device user group administrator: Responsible for maintenance of mobile device accounts, including setup, change of account configurations, and account deletion. Responsible for defining which apps user groups or individual users have access to in the MAS. Can only perform administrative functions assigned by the security configuration administrator.
- Auditor: Responsible for reviewing and maintaining server and mobile device audit logs.

SFR ID: FMT_SMR.1.1(1)'
  desc 'check', 'Review the MaaS360 server console and confirm that different roles (administrator, auditor, user) are created with different levels of privileges, providing separation of duties for different users/groups.

On the MaaS360 console, complete the following steps:
1. Go to Setup >> Roles.
2. Verify all required roles are listed. (Note: Role titles may be different than listed in the requirement statement.)
3. Select applicable role and select "edit", and then verify the role has the appropriate rights to access based on vulnerability description of this requirement statement (check).

If the MaaS360 server does not have all required roles and the roles do not have appropriate rights, this is a finding.'
  desc 'fix', 'On the MaaS360 console, complete the following steps for each role:
1. Go to Setup >> Roles.
2. Select the "Add Role" button.
3. Under "Basic Information", input the Role Name and Role Description.
4. Under "Select Mode of Creation", click on the "Create new" bubble and then click "Next".
5. Under "Grant Access Rights", select the appropriate rights for the role and then click "Save".'
  impact 0.5
  ref 'DPMS Target IBM MaaS360 with Watson v10.x MDM'
  tag check_id: 'C-81967r1_chk'
  tag severity: 'medium'
  tag gid: 'V-82167'
  tag rid: 'SV-96881r1_rule'
  tag stig_id: 'M360-10-007100'
  tag gtitle: 'PP-MDM-311058'
  tag fix_id: 'F-89023r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002226', 'CCI-002227']
  tag nist: ['CM-6 b', 'AC-6 (5)', 'AC-6 (5)']
end
