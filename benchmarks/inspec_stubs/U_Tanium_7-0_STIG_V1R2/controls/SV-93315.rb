control 'SV-93315' do
  title 'Role-based system access must be configured to least privileged access to Tanium Server functions through the Tanium interface.'
  desc 'User accessibility to various Tanium Server functions performed via the console can be restricted by User Roles. Those User Roles are: Administrator, Read Only User, Question Author, Action User, Action Approver, Action Author, Sensor Author, Action/Sensor Author, and Content Administrator. These are already configured in Tanium.

System access should be reviewed periodically to verify that all Tanium users are assigned the appropriate role, with the least privileged access possible to perform assigned tasks being the recommended best practice. Consider removing users that have not logged onto the system within a predetermined time frame.'
  desc 'check', "Consult with the Tanium System Administrator to review the documented list of Tanium users.

Analyze the users configured in the Tanium interface.

Review the users' respective approved roles, as well as the correlated Active Directory security group for the User Roles.

Validate Active Directory security groups/Tanium roles are documented to assign least privileged access to the functions of the Tanium Server through the Tanium interface.

If the documentation does not reflect a granular, least privileged access approach to the Active Directory Groups/Tanium Roles assignment, this is a finding."
  desc 'fix', "Analyze the users configured in the Tanium interface.

Determine least privileged access required for each user to perform their respective duties.

Move users to the appropriate Active Directory security group in order to ensure the user is synced to the appropriate Tanium User Role.

If appropriate Active Directory security groups are not already configured, create the groups and add the appropriate users.

Ensure AD sync re-populates the Tanium Users' associated Roles accordingly."
  impact 0.7
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78179r1_chk'
  tag severity: 'high'
  tag gid: 'V-78609'
  tag rid: 'SV-93315r1_rule'
  tag stig_id: 'TANS-CN-000006'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-85345r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
