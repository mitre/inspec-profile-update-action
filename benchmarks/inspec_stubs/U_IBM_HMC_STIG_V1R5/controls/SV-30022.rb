control 'SV-30022' do
  title 'Predefined task roles to the Hardware Management Console (HMC) must be specified to limit capabilities of individual users.'
  desc 'Individual task roles with access to specific resources if not created and restricted, will allow unrestricted access to system functions. The following is an example of some managed resource categories: Tasks are functions that a user can perform, and the managed resource role defines where those tasks might be carried out. The Access Administrator assigns a user ID and user roles to each user of the Hardware Management Console. 

•	OPERATOR OPERATOR 
•	ADVANCED ADVANCED OPERATOR
•	ACSADMIN ACCESS ADMINISTRTOR
•	SYSPROG SYSTEM PROGRAMMER
•	SERVICE SRVICE REPRESENTATIVE
Failure to establish this environment may lead to uncontrolled access to system resources.'
  desc 'check', 'Have the System Administrator display the user profiles and demonstrate that valid users are defined to valid roles and that authorities are restricted to the site list of users.

Note: Sites must have a list of valid HMC users, indicating their USER IDs, Date of DD2875, and roles and responsibilities.

To display user roles chose User Profiles and then select the user for modification. View Task Roles and Manager Resources Roles.

If the different roles are not properly displayed or are not properly restricted, then this is a FINDING.'
  desc 'fix', 'The System Administrator must set up a list of Users

Note: Sites must have a list of valid HMC users, indicating their USER IDs, Date of DD2875, and roles and responsibilities  
and these must match the users defined to the HMC.

To display user roles chose User Profiles and then select the user for modification. View Task Roles and Manager Resources Roles.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-29860r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24354'
  tag rid: 'SV-30022r2_rule'
  tag stig_id: 'HMC0090'
  tag gtitle: 'HMC0090'
  tag fix_id: 'F-26744r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
