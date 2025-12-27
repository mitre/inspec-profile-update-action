control 'SV-95137' do
  title 'The Bromium Enterprise Controller (BEC) must protect BEC Web console  from unauthorized modification.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

The BEC Web console can gives a view of events, threat conditions, policies, and client information and thus is considered an audit tool. BEC does not allow the integration of other audit tool provided by third-party vendors. The BEC Web console access is configured in Settings >> Users.'
  desc 'check', 'Obtain a list of users who are authorized read-only permissions to the BEC Web console from the site representative. Verify these users are configured for read-only access.

Navigate to the Setting menu and identify Roles with read-only access. These roles will have one or more of the following privileges checked:

- View device events
- View policies
- View events
- View threats
- View users
- View user groups

Identify the Groups that are assigned these Roles:

1. From the BEC console, click on "Settings".
2. Select User Groups.
3. Click on each group and see if one of the read-only roles is assigned.

Verify the list of users with read-only privileges is assigned only to one of the Groups with a read-only Role.

If users who are authorized for read-only privileges are assigned to groups with modification access, this is a finding.'
  desc 'fix', 'Configure the BEC Web console to restrict users who are authorized for view (read) permissions only.

Configure Role with View privileges only:

1. From the BEC console, click on "Settings".
2. Select "Roles".
3. To create a new Role, click on "User Options" and select "Add Role".
4. Create a name for the Role (with optional description) - select any of the following privileges:
- View device events
- View policies
- View events
- View threats
- View users
- View user groups
5. Click "Save Changes".

Configure Group with Read-Only Role assigned to it:

1. From the BEC console, click on "Settings".
2. Select User Groups.
3. To create a new group, click on "User Options" and select "Add User Group".
4. Create a name (with optional description) for the Group.
5. (Optional) - Synchronize Group with existing Group within Active Directory.
6. From the Role drop-down menu, select read-only Role.
7. Click "Add User Group".

1. From the BEC console, click on "Settings".  
2. Select "Users".
3. Click User Options >> Add User.  
4. Add new user and their Active Directory details.
5. Using the drop-down list, assign new view only user the read-only Group.'
  impact 0.5
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80105r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80433'
  tag rid: 'SV-95137r1_rule'
  tag stig_id: 'BROM-00-000250'
  tag gtitle: 'SRG-APP-000122'
  tag fix_id: 'F-87239r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
