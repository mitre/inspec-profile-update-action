control 'SV-31555' do
  title 'Access to the Hardware Management Console (HMC) must be restricted by assigning users proper roles and responsibilities.'
  desc 'Access to the HMC if not properly controlled and restricted by assigning users proper roles and responsibilities, could allow modification to areas outside the need-to-know and abilities of the individual resulting in a bypass of security and an altering of the environment. This would result in a loss of secure operations and can cause an impact to data operating environment integrity.'
  desc 'check', 'Have the System Administrator verify to the reviewer that the Roles and Responsibilities assigned are assigned to the proper individuals by their areas of responsibility.

Note: Sites must have a list of valid HMC users, indicating their USERID, Date of DD2875, and roles and responsibilities.

Have the System Administrator verify to the reviewer that the Roles and Responsibilities assigned are assigned to the proper individuals by their areas of responsibility.

To display user roles chose User Profiles and then select the user for modification. View Task Roles and Manager Resources Roles.

If the HMC user-IDs displayed by the System Administrator are not properly assigned by Roles and Responsibilities, then this is a FINDING.'
  desc 'fix', 'Have the System Administrator using the list user IDs and responsibilities, validate that each user is properly specified in the HMC based on his/her roles and responsibilities.
 
Note: Sites must have a list of valid HMC users, indicating their USERID, Date of DD2785, roles and responsibilities

To display user roles choose User Profiles and then select the user for modification. View Task Roles and Manager Roles.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-31828r1_chk'
  tag severity: 'medium'
  tag gid: 'V-25386'
  tag rid: 'SV-31555r2_rule'
  tag stig_id: 'HMC0045'
  tag gtitle: 'HMC0045'
  tag fix_id: 'F-28328r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAN-1, ECLP-1, PRMP-1, PRMP-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
