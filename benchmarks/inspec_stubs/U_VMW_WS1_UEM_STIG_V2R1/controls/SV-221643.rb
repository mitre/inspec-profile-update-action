control 'SV-221643' do
  title 'The Workspace ONE UEM server must be configured to have at least one user in the following Administrator roles: Server primary administrator, security configuration administrator, device user group administrator, or auditor.'
  desc 'Having several administrative roles for the Workspace ONE UEM server supports separation of duties. This allows administrator-level privileges to be granted granularly, such as giving application management privileges to one group and security policy privileges to another group. This helps prevent administrators from intentionally or inadvertently altering other settings and configuration, which they may not understand or approve of, that can weaken overall security and increase the risk of compromise.

- Server primary administrator: Responsible for server installation, initial configuration, and maintenance functions. Responsible for the setup and maintenance of security configuration administrator and auditor accounts. Responsible for the maintenance of applications in the MAS.
- Security configuration administrator: Responsible for security configuration of the server, defining device user groups, setup and maintenance of device user group administrator accounts, and defining privileges of device user group administrators.
- Device user group administrator: Responsible for maintenance of mobile device accounts, including setup, change of account configurations, and account deletion. Responsible for defining to which apps user groups or individual users have access in the MAS. Can only perform administrative functions assigned by the security configuration administrator.
- Auditor: Responsible for reviewing and maintaining server and mobile device audit logs.

SFR ID: FMT_SMR.1.1(1)'
  desc 'check', 'Review the Workspace ONE UEM server configuration settings and verify the server is configured with the Administrator roles: 
- Server primary administrator
- Security configuration administrator
- Device user group administrator
- Auditor

On the MDM console, do the following:
1. Authenticate to the Workspace ONE UEM console.
2. Navigate to Accounts >> Administrators >> Roles.
3. From the Roles page, examine the currently defined roles under the "General Info" heading. Each role can be selected for examination by clicking on the name link. Each role will have a set of attributes for which that role has been granted: "Read", "Edit", or no access. 

If the MDM console administrative role is not present or the role attributes are not set to organizational standards, this is a finding.'
  desc 'fix', 'Configure the Workspace ONE UEM server with the Administrator roles:
- Server primary administrator
- Security configuration administrator
- Device user group administrator
- Auditor

On the MDM console, do the following:
1. Authenticate to the Workspace ONE UEM console.
2. Navigate to Accounts >> Administrators >> Roles.
3. From the Roles page, click "Add Role".
4. Name the role according to the organization standard for the function and provide a role description.
5. Add role attributes by selecting each of the role categories ensuring "Read" and/or "Edit" are selected appropriately for each function for the role. A default set will be checked but should be reviewed and overridden as appropriate to the role.
6. After reviewing the choices in each category and verifying correctness, click "Save" to save the new role.'
  impact 0.5
  ref 'DPMS Target VMware Workspace ONE UEM'
  tag check_id: 'C-23358r416767_chk'
  tag severity: 'medium'
  tag gid: 'V-221643'
  tag rid: 'SV-221643r588007_rule'
  tag stig_id: 'VMW1-00-000560'
  tag gtitle: 'PP-MDM-411058'
  tag fix_id: 'F-23347r416768_fix'
  tag 'documentable'
  tag legacy: ['SV-111381', 'V-102329']
  tag cci: ['CCI-000366', 'CCI-002226', 'CCI-002227']
  tag nist: ['CM-6 b', 'AC-6 (5)', 'AC-6 (5)']
end
