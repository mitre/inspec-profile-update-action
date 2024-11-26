control 'SV-30008' do
  title 'Access to the Hardware Management Console must be restricted to only authorized personnel.'
  desc 'Access to the Hardware Management Console if not properly restricted to authorized personnel could lead to a bypass of security, access to the system, and an altering of the environment. This would result in a loss of secure operations and can cause an impact to data operating environment integrity.'
  desc 'check', 'Verify that sign-on access to the Hardware Management Console is restricted to authorize personnel and that a DD2875 is on file for each user ID. 

Note: Sites must have a list of valid HMC users, indicating their USER IDs, Date of DD2875, and roles and responsibilities

To display user roles chose User Profiles and then select the user for modification. View Task Roles and Manager Resources Roles.

If each user displayed by the System Administrator does not have a DD2875, then this is a FINDING.'
  desc 'fix', 'The System Administrator will see that sign-on access to the Hardware Management Console is restricted to authorized personnel and that a DD2875 is on file for each user ID. 

Note: Sites must have a list of valid HMC users, indicating their USER IDs, Date of DD2875, and roles and responsibilities.

The System Administrator must see that the list and users defined to the Hardware Management Console match.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-30366r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24349'
  tag rid: 'SV-30008r2_rule'
  tag stig_id: 'HMC0040'
  tag gtitle: 'HMC0040'
  tag fix_id: 'F-26667r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Manager', 'Security Manager']
  tag ia_controls: 'ECLP-1, PECF-1, PECF-2, PRMP-1, PRMP-2'
  tag cci: ['CCI-002227', 'CCI-002235']
  tag nist: ['AC-6 (5)', 'AC-6 (10)']
end
