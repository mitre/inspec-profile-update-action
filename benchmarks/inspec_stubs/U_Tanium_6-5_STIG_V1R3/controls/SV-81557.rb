control 'SV-81557' do
  title 'The Tanium Application Server must protect audit tools from unauthorized modification.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', "Consult with the Tanium System Administrator to review the documented list of Tanium users. 

Review the users' respective approved roles, as well as the correlated Active Directory security group for the User Roles.

Validate Active Directory security groups/Tanium roles are documented to assign a least privileged access to the functions of the Tanium Server through the Tanium interface.

If the documentation does not reflect a granular, least privileged access approach to the Active Directory Groups/Tanium Roles assignment, this is a finding."
  desc 'fix', "Analyze the users configured in the Tanium interface.

Determine least privileged access required for each user to perform their respective duties.

Move users to the appropriate Active Directory security group in order to ensure the user is synced to the appropriate Tanium User Role.

If appropriate Active Directory security groups are not already configured, create the groups and add the appropriate users.

Ensure AD sync re-populates the Tanium Users' associated Roles accordingly."
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67703r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67067'
  tag rid: 'SV-81557r1_rule'
  tag stig_id: 'TANS-SV-000012'
  tag gtitle: 'SRG-APP-000122'
  tag fix_id: 'F-73167r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
