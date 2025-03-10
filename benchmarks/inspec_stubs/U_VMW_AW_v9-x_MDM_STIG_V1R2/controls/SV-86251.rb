control 'SV-86251' do
  title 'The AirWatch MDM Server must be configured with the Administrator roles:
a. MD user
b. Server primary administrator
c. Security configuration administrator
d. Device user group administrator
e. Auditor.'
  desc 'Having several roles for the MDM Server supports separation of duties. This allows administrator-level privileges to be granted granularly, such as giving application management privileges to one group and security policy privileges to another group. This helps prevent administrators from intentionally or inadvertently altering other settings and configurations they may not understand or approve of, which can weaken overall security and increase the risk of compromise.

Server primary administrator: responsible for server installation, initial configuration, and maintenance functions. Responsible for the setup and maintenance of Security configuration administrator and Auditor accounts. (Note: Many of these responsibilities are not AirWatch MDM Server Roles, but Host Operating System roles) 

-Security configuration administrator: responsible for security configuration of the server, setting up and maintenance of mobile device security policies, defining device user groups, setup and maintenance of device user group administrator accounts, and defining privileges of device user group administrators. (Note: Many of these responsibilities are not AirWatch MDM Server Roles, but Host Operating System roles) 

-Device user group administrator: responsible for maintenance of mobile device accounts, including setup, change of account configurations, and account deletion. Can only perform administrative functions assigned by the Security configuration administrator. 

-Auditor: responsible for reviewing and maintaining server and mobile device audit logs. (Note: Many of these responsibilities are not AirWatch MDM Server Roles, but Host Operating System roles)

SFR ID: FMT_SMR.1.1(1) Refinement'
  desc 'check', 'Review the AirWatch MDM Server configuration settings, and verify the server is configured with the Administrator roles:

a. MD user;
b. Server primary administrator;
c. Security configuration administrator;
d. Device user group administrator; and 
e. Auditor. 

AirWatch Roles are fully customizable by the Organization with hundreds of Actions available to choose Read or Edit capabilities, can be edited to match DoD Titles and responsibilities.

On the AirWatch console complete the following procedure to verify permissions assigned to a custom organization role:

1. Enter the administration console.
2. Choose “Accounts”.
3. Choose “Administrators”.
4. Choose “Roles”.
5. Verify all required DoD roles are listed.
6. Choose each DoD role inturn.
7. In “Categories”, navigate to appropriate responsibilities and Choose responsibility.
8. In “Accounts”, verify proper Read or Edit functions for each action item. See the Vulnerability Description for the required responsibilities for each role.

On the AirWatch console complete the following procedure to verify that users are assigned to particular Roles:

1. Enter the administration console.
2. Choose “Accounts”.
3. Choose “Administrators”.
4. Choose "List View".
5. In "Username" column, verify user name.
6. In "Role" column, verify there is an authorized Administrator assigned to each organization required role.

If each required administrator role is not set up on the MDM console or each required role is not assigned required responsibilities or at least one user is not assigned to each role, this is a finding.'
  desc 'fix', 'Some DoD Roles are created managed by Server OS. Server OS Security Target and STIGs should be referenced for these items.

AirWatch Roles are full customizable by the Organization with hundreds of Actions available to choose Read or Edit capabilities, can be edited to match DoD Titles and responsibilities.

On the AirWatch console complete the following procedure to create custom Organization specified roles:

1. Enter the administration console.
2. Choose “Accounts”.
3. Choose “Administrators”.
4. Choose “Roles”.
5. Choose “Add Roles”.
6. Type DoD-Approved Title in “Name” block, and summary of Role in “Description” block.
7. In “Categories”, navigate to appropriate responsibilities and Choose Responsibility. See the Vulnerability Description for the required responsibilities for each role.
8. In “Accounts”, select proper Read or Edit functions for each action item.
9. Choose “Save”.

On the AirWatch console complete the following procedure to create a local AirWatch Administrator and associate with a custom Organization specified role:

1. Enter the administration console.
2. Choose “Accounts”.
3. Choose “Administrators”.
4. Choose "List View".
5. Choose "Add".
6. Choose "Add Admin".
7. To create local AirWatch Admin, fill out required user information on "Basic" Tab. To import Active Directory user (Admin will use Active Directory credentials to access MDM Console), choose "Directory" tab, enter User Name, and choose "Check User".
8. Choose "Roles" tab.
9. Click in "Organization Group" box and choose Organization Group level of AirWatch MDM Console the Administrator will have Role privileges to manage.
10. Click in "Role" box, and choose customer organizational role to assign Admin.
11. Choose "Save".'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 9.x'
  tag check_id: 'C-71957r4_chk'
  tag severity: 'medium'
  tag gid: 'V-71627'
  tag rid: 'SV-86251r1_rule'
  tag stig_id: 'VMAW-09-000080'
  tag gtitle: 'PP-MDM-202105'
  tag fix_id: 'F-77953r4_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
