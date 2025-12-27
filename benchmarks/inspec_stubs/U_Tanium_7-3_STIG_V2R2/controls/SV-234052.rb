control 'SV-234052' do
  title 'Role-based system access must be configured to least privileged access to Tanium Server functions through the Tanium interface.'
  desc 'User accessibility to various Tanium Server functions performed via the console can be restricted by functional roles, a combination of User Role(s), and Content Set(s) assigned through User Group membership. Functional roles are assigned to users via Active Directory Group membership.

System access should be reviewed periodically to verify that all Tanium users are assigned the appropriate functional role, with the least privileged access possible to perform assigned tasks being the recommended best practice. Consider removing users that have not logged onto the system within a predetermined time frame.'
  desc 'check', "Consult with the Tanium System Administrator to review the documented list of Tanium users.

Analyze the users configured in the Tanium interface.

Review the users' respective approved roles, as well as the correlated Active Directory Group for the Tanium functional roles.

Validate Active Directory Groups/Tanium functional roles are documented to assign least privileged access to the functions of the Tanium Server through the Tanium interface.

If the documentation does not reflect a granular, least privileged access approach to the Active Directory Groups/Tanium functional roles assignment, this is a finding."
  desc 'fix', "Analyze the users configured in the Tanium interface.

Determine least privileged access required for each user to perform their respective duties.

Move users to the appropriate Active Directory Group in order to ensure the user is synced to the appropriate Tanium functional role.

If appropriate Active Directory Groups are not already configured, create the Groups and add the appropriate users.

Ensure LDAP sync repopulates the Tanium Users' associated functional roles accordingly."
  impact 0.7
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37237r610656_chk'
  tag severity: 'high'
  tag gid: 'V-234052'
  tag rid: 'SV-234052r612749_rule'
  tag stig_id: 'TANS-CN-000006'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-37202r610657_fix'
  tag 'documentable'
  tag legacy: ['SV-102177', 'V-92075']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
