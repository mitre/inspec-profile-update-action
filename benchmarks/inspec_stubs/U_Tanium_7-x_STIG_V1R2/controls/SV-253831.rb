control 'SV-253831' do
  title 'The Tanium application must prohibit user installation, modification, or deletion of software without explicit privileged status.'
  desc 'Allowing regular users to install, modify, or delete software, without explicit privileges, creates the risk that the application performs in a manner inconsistent with its design. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceed the rights of a regular user.

Application functionality will vary, and while users are not permitted to install unapproved applications, there may be instances where the organization allows the user to install approved software packages, such as from an approved software repository.

The application must enforce software installation by users based on what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization.

'
  desc 'check', %q(1. Consult with the Tanium system administrator to review the documented list of Tanium users.

2. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication. 
 
3. Click "Administration" on the top navigation banner.
 
4. Under "Permissions", select "Users".
 
5. Review the users' respective approved roles, as well as the correlated LDAP security group for the User Roles.

6. Validate LDAP security groups/Tanium roles are documented to assign least privileged access to the functions of the Tanium Server through the Tanium interface.

If the documentation does not reflect a granular, least privileged access approach to the LDAP Groups/Tanium Roles assignment, this is a finding.)
  desc 'fix', %q(1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication. 
 
2. Click "Administration" on the top navigation banner.
 
3. Under "Permissions", select "Users".

4. Analyze the users configured in the Tanium interface. 

5. Determine least privileged access required for each user to perform their respective duties. 

6. Move users to the appropriate LDAP security group to ensure the user is synced to the appropriate Tanium User Role. 

7. If the appropriate LDAP security groups are not already configured, create the groups and add the appropriate users. 

8. Ensure LDAP sync repopulates the Tanium Users' associated Roles accordingly.)
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57283r842519_chk'
  tag severity: 'medium'
  tag gid: 'V-253831'
  tag rid: 'SV-253831r858413_rule'
  tag stig_id: 'TANS-CN-000036'
  tag gtitle: 'SRG-APP-000121'
  tag fix_id: 'F-57234r842520_fix'
  tag satisfies: ['SRG-APP-000122; SRG-APP-000123']
  tag 'documentable'
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9', 'AU-9']
end
