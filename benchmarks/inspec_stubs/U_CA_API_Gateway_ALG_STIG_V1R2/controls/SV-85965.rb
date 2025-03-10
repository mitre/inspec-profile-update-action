control 'SV-85965' do
  title 'The CA API Gateway must protect audit tools from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Network elements providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make decisions regarding access to audit tools.

There is only one tool used to view audited events within the CA API Gateway. That tool is the CA API Gateway - Policy Manager. Use of this tool must be granted and policed by the organization, only allowing individuals access as needed in accordance with the organizational requirements.'
  desc 'check', 'Open the CA API Gateway - Policy Manager as an administrative user. 

Select "Tasks" from the main menu and chose "Manage Roles". 

Verify that only the authorized users of the tool have been granted their respective roles. 

If any user has not been granted the proper role(s), this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager as an administrator. 

Select "Tasks" from the main menu and chose "Manage Roles".

Select the "View Audit Records" Role and Add/Assign the users that are authorized to view the audited events as per organizational policy. 

Assign any other roles to authorized users as per organizational policy.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71741r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71341'
  tag rid: 'SV-85965r1_rule'
  tag stig_id: 'CAGW-GW-000260'
  tag gtitle: 'SRG-NET-000101-ALG-000059'
  tag fix_id: 'F-77651r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
