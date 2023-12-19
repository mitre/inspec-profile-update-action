control 'SV-254938' do
  title 'The Tanium application must prohibit user installation of software without explicit privileged status.'
  desc 'Allowing regular users to install software without explicit privileges creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.

Application functionality will vary, and while users are not permitted to install unapproved applications, there may be instances where the organization allows the user to install approved software packages such as from an approved software repository. 

The application must enforce software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization. 

This requirement applies, for example, to applications that provide the ability to extend application functionality (e.g., plug-ins, add-ons) and software management applications.'
  desc 'check', "Consult with the Tanium System Administrator to review the documented list of Tanium users.

1. Review the users' respective approved roles, as well as the correlated LDAP security group for the User Roles.

2. Validate LDAP security groups/Tanium roles are documented to assign least privileged access to the functions of the Tanium Server through the Tanium interface.

If the documentation does not reflect a granular, least privileged access approach to the LDAP Groups/Tanium Roles assignment, this is a finding."
  desc 'fix', %q(1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 
 
2. Click "Administration" on the top navigation banner.
 
3. Under Permissions, select "Users".

4. Analyze the users configured in the Tanium interface.

5. Determine least privileged access required for each user to perform their respective duties.

6. Move users to the appropriate LDAP security group to ensure the user is synced to the appropriate Tanium User Role.

7. If the appropriate LDAP security groups are not already configured, create the groups and add the appropriate users.

8. Ensure LDAP sync repopulates the Tanium users' associated roles accordingly.)
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58551r867712_chk'
  tag severity: 'medium'
  tag gid: 'V-254938'
  tag rid: 'SV-254938r867714_rule'
  tag stig_id: 'TANS-AP-000940'
  tag gtitle: 'SRG-APP-000378'
  tag fix_id: 'F-58495r867713_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
