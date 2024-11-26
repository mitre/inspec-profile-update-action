control 'SV-80123' do
  title 'The MaaS360 Server must be configured with the Administrator roles:

a. MD user;
b. Server primary administrator;
c. Security configuration administrator;
d. Device user group administrator;
e. Auditor.'
  desc 'Having several roles for the MaaS360 Server supports separation of duties. This allows administrator-level privileges to be granted granularly, such as giving application management privileges to one group and security policy privileges to another group. This helps prevent administrators from intentionally or inadvertently altering other settings and configurations they may not understand or approve of, which can weaken overall security and increase the risk of compromise.

Roles
a. MD user:  able to log into the application store and request approved applications
b. Server primary administrator: primary administrator for the server, including server installation, configuration, patching, and setting up admin accounts.
c. Security configuration administrator:  Has the ability to define new policies but not to push them to managed mobile devices.
d. Device user group administrator:  Has the ability to set up new user accounts, add devices, and push security policies and issue administrative commands to managed mobile devices or MDM agents.  
e. Auditor:  Has the ability to set audit configuration parameters and delete or modify the content of logs.

SFR ID: FMT_SMR.1.1(1) Refinement'
  desc 'check', 'Review the MaaS360 server console and confirm that different roles (administrator, auditor, user) are created with different levels of privileges providing separation of duties for different users/groups.

On the MaaS360 console complete the following steps:
1. Go to Setup >> Roles
2. Verify all required roles are listed (Note: Role titles maybe different than listed in the requirement statement)
3. Select applicable role and select "edit", then verify that the role has the appropriate rights based on description in Vulnerability description.

If the MaaS360 server does all required roles and the roles do not have appropriate rights, this is a finding.'
  desc 'fix', 'On the MaaS360 console complete the following steps:
1. For each role do the following
2. Go to Setup >> Roles
3. Select the "Add Role" Button
4. Under "Basic Information" Input the Role Name and Role Description
5. Under "Select Mode of Creation" click on the "Create new" bubble and then click Next
6. Under "Grant Access Rights" select the appropriate rights for the role and then click Save'
  impact 0.5
  ref 'DPMS Target IBM MaaS360 v2.3.x MDM'
  tag check_id: 'C-66193r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65633'
  tag rid: 'SV-80123r1_rule'
  tag stig_id: 'M360-01-000700'
  tag gtitle: 'PP-MDM-202105'
  tag fix_id: 'F-71561r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
