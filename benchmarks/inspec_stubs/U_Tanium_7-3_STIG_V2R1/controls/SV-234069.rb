control 'SV-234069' do
  title 'The Tanium application must prohibit user installation of software without explicit privileged status.'
  desc 'Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.

Application functionality will vary, and while users are not permitted to install unapproved applications, there may be instances where the organization allows the user to install approved software packages such as from an approved software repository.

The application must enforce software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization.

This requirement applies, for example, to applications that provide the ability to extend application functionality (e.g., plug-ins, add-ons) and software management applications.

'
  desc 'check', "Consult with the Tanium System Administrator to review the documented list of Tanium users.

Review the users' respective approved roles, as well as the correlated Active Directory security group for the User Roles.

Validate Active Directory security groups/Tanium roles are documented to assign least privileged access to the functions of the Tanium Server through the Tanium interface.

If the documentation does not reflect a granular, least privileged access approach to the Active Directory Groups/Tanium Roles assignment, this is a finding."
  desc 'fix', "Analyze the users configured in the Tanium interface.

Determine least privileged access required for each user to perform their respective duties.

Move users to the appropriate Active Directory security group in order to ensure the user is synced to the appropriate Tanium User Role.

If the appropriate Active Directory security groups are not already configured, create the groups and add the appropriate users.

Ensure LDAP sync repopulates the Tanium Users' associated Roles accordingly."
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37254r610707_chk'
  tag severity: 'medium'
  tag gid: 'V-234069'
  tag rid: 'SV-234069r612749_rule'
  tag stig_id: 'TANS-CN-000036'
  tag gtitle: 'SRG-APP-000378'
  tag fix_id: 'F-37219r610708_fix'
  tag satisfies: ['SRG-APP-000378', 'SRG-APP-000380', 'SRG-APP-000121', 'SRG-APP-000122', 'SRG-APP-000123']
  tag 'documentable'
  tag legacy: ['SV-102211', 'V-92109']
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-001812', 'CCI-001813']
  tag nist: ['AU-9 a', 'AU-9', 'AU-9', 'CM-11 (2)', 'CM-5 (1) (a)']
end
