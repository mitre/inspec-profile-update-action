control 'SV-93347' do
  title 'Tanium must prohibit user installation of software without explicit privileged status and enforce access restrictions associated with changes to application configuration.'
  desc 'Allowing regular users to install software without explicit privileges creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.

Application functionality will vary, and while users are not permitted to install unapproved applications, there may be instances where the organization allows the user to install approved software packages such as from an approved software repository.

The application must enforce software installation by users based on what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization.

This requirement applies, for example, to applications that provide the ability to extend application functionality (e.g., plug-ins, add-ons) and software management applications.

Failure to provide logical access restrictions associated with changes to application configuration may have significant effects on the overall security of the system.

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

Accordingly, only qualified and authorized individuals should be allowed to obtain access to application components for the purposes of initiating changes, including upgrades and modifications.

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).

'
  desc 'check', "Consult with the Tanium System Administrator to review the documented list of Tanium users.

Review the users' respective approved roles, as well as the correlated Active Directory security group for the User Roles.

Validate Active Directory security groups/Tanium roles are documented to assign least privileged access to the functions of the Tanium Server through the Tanium interface.

If the documentation does not reflect a granular, least privileged access approach to the Active Directory Groups/Tanium Roles assignment, this is a finding."
  desc 'fix', "Analyze the users configured in the Tanium interface.

Determine least privileged access required for each user to perform their respective duties.

Move users to the appropriate Active Directory security group in order to ensure the user is synced to the appropriate Tanium User Role.

If appropriate Active Directory security groups are not already configured, create the groups and add the appropriate users.

Ensure AD sync repopulates the Tanium users' associated Roles accordingly."
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78211r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78641'
  tag rid: 'SV-93347r1_rule'
  tag stig_id: 'TANS-CN-000036'
  tag gtitle: 'SRG-APP-000378'
  tag fix_id: 'F-85377r1_fix'
  tag satisfies: ['SRG-APP-000378', 'SRG-APP-000380']
  tag 'documentable'
  tag cci: ['CCI-001812', 'CCI-001813']
  tag nist: ['CM-11 (2)', 'CM-5 (1) (a)']
end
